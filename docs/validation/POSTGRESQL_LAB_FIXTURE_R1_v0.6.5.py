#!/usr/bin/env python3
"""Prepare synthetic offline evidence in a new private fixture; no database access."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parents[2]
for folder in ('evidence_bundle','ingestion','asset_resolver'):
    sys.path.insert(0,str(ROOT/folder))
import P01_Evidence_Bundle as bundle
import P01_Offline_Import as offline
import P01_Asset_Resolver as resolver
VERSION='0.6.5'
ASSESSMENT_ID='P01-PG-LAB-R1'


def write(path,doc,sidecar=False):
    path.write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    if sidecar:
        path.with_suffix(path.suffix+'.sha256').write_text(bundle.digest_file(path)+'  '+path.name+'\n')
    return path


def prepare(lab_root):
    root=Path(lab_root).expanduser().resolve()
    root.mkdir(parents=True,exist_ok=True)
    base=root/('P01-PG-R1-'+uuid.uuid4().hex[:12]);base.mkdir(mode=0o700)
    store=base/'server-store'
    manifest={'schema_version':'0.4b.6','assessment_id':ASSESSMENT_ID,'environment_label':'OFFLINE-SYNTHETIC-LAB',
              'authorized_scopes':['192.0.2.0/24'],'exclude_scopes':[],'domains':[],
              'allowed_protocols':['winrm'],'discovery_nodes':[],
              'safety_policy':{'default_concurrency':1,'max_actions':1,'require_authorized_ack':True,'auto_expand_scope':False}}
    imports=[]
    for index,positive in enumerate((True,False)):
        folder=base/('positive' if positive else 'negative');folder.mkdir()
        network={'metadata':{'scanner_name':'P01-Network-Discovery-Scanner','scanner_version':'synthetic',
                             'run_label':'PG-LAB-FIXTURE'},
                 'assets':[{'ip':'192.0.2.10','hostname':'fixture01.example.test','mac':'00:11:22:33:44:55',
                            'device_type_guess':'Windows Host','os_guess':'Windows','confidence':'High',
                            'open_ports':[{'port':5985,'protocol':'tcp','service':'winrm-http'}]}]}
        target={'metadata':{'executor_name':'P01-Credentialed-Discovery-Executor','executor_version':'synthetic',
                            'run_label':'PG-LAB-FIXTURE','secret_values_persisted_to_output':False},
                'action':{'target_ip':'192.0.2.10','hostname':'fixture01.example.test','protocol':'winrm',
                          'port':5985,'device_type':'Windows Host','os_family':'Windows','realm':'FIXTURE'},
                'authentication':{'success':True},
                'enrichment':{'collection_status':'collected',
                              'identity':{'computer_name':'FIXTURE01','fqdn':'fixture01.example.test',
                                          'serial_number':'SYNTHETIC-PG-R1','domain':'example.test',
                                          'part_of_domain':True,'domain_role':1},
                              'operating_system':{'caption':'Synthetic Windows'},
                              'network':{'interfaces':[{'interface_alias':'Fixture','ipv4':[{'address':'192.0.2.10','prefix_length':24}]}]},
                              'collection_sections':[{'section':section,'success':True,'status_code':0}
                                                     for section in ('identity','firewall','secure_channel')],
                              'security':{'firewall_profiles':[{'name':name,'enabled':not(positive and name=='Public')}
                                                               for name in ('Domain','Private','Public')],
                                          'secure_channel_checked':True,'secure_channel_healthy':not positive}}}
        net=write(folder/'network.json',network,True);evidence=write(folder/'target.json',target,True)
        context=write(folder/'assessment.json',manifest)
        resolved=write(folder/'resolved.json',resolver.resolve(net,[evidence],context),True)
        package=folder/'fixture.p01bundle'
        bundle.create_bundle(package,ASSESSMENT_ID,'PG-R1-'+str(index+1),'P01-LAB-FIXTURE',
                             net,[evidence],context,resolved,require_evidence_sidecars=True)
        imported=offline.import_bundle(package,store,process=False,require_outer_sidecar=True)
        imports.append({'bundle_id':imported['bundle_id'],'import_dir':imported['import_dir']})
    doc={'status':'POSTGRESQL LAB FIXTURE READY','fixture_version':VERSION,'offline_synthetic':True,
         'fixture_directory':str(base),'store_dir':str(store),'assessment_id':ASSESSMENT_ID,'imports':imports,
         'fixture_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'expected_after_projection':{'imports':2,'central_assets':1,'observations':2,'analyses':2,
                                      'evaluations':4,'recorded_finding_occurrences':2,
                                      'finding_outcomes':2,'no_finding_outcomes':2}}
    write(base/'fixture-summary.json',doc,True)
    return doc


def cli(argv=None):
    parser=argparse.ArgumentParser(description='Cancã isolated offline PostgreSQL LAB fixture')
    parser.add_argument('--lab-root',required=True)
    args=parser.parse_args(argv)
    try:
        print(json.dumps(prepare(args.lab_root),ensure_ascii=False));return 0
    except Exception:
        print(json.dumps({'status':'failed','error_code':'fixture_failed','fixture_version':VERSION}));return 2


if __name__=='__main__':raise SystemExit(cli())
