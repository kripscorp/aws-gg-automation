#!/usr/bin/env python3

import os
import json
import yaml
import boto3

#PROFILE_NAME='aws-profile'
#REGION='us-east-1'

SESSION = boto3.Session(profile_name='<aws profile>', region_name='us-east-1')
GG = SESSION.client('greengrass')
IOT = SESSION.client('iot')

def check_greengrass_group(group_name):
    """
        Input: greengrass group name 
        output: True if greengrass group is found 
        output: False if greengrass group is not found
    """
    response = GG.list_groups()
    group_flag = False
    for group in response['Groups']:
        if group["Name"] == group_name:
            group_flag = True
            break
    return group_flag

def create_greengrass_group(group_name):
    """
        input: greengrass group name 
        output: greengrass group creation arn status
    """
    group = GG.create_group(Name=group_name)
    return group

def create_certs():
    """
        output: keys_cert
    """
    keys_certs = IOT.create_keys_and_certificate(setAsActive=True)
    return keys_certs

def create_thing_type(name, description):
    """
        input: thing type name
        input: thing type description
        output: response of thing creation
    """
    response = IOT.create_thing_type(
        thingTypeName=name,
        thingTypeProperties={
            'thingTypeDescription': description
            }
        )
    return response

def create_thing(thing_name, thing_type):
    """
        input: thing name 
        input: thing type
        output response
    """
    response = IOT.create_thing(thingName=thing_name, thingTypeName=thing_type)
    return response

def attach_thing_and_principal(thing_name, certificate_arn):
    """
        input: thing name
        input: certificate arn
        output: response
    """
    response = IOT.attach_thing_principal(
            thingName = thing_name,
            principal = certificate_arn
            )
    return response

def create_policy(name):
    """
        input: policy name 
        output: policy creation arn
    """
    core_policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                         "Effect": "Allow",
                         "Action": [
                             "iot:Publish", 
                             "iot:Subscribe", 
                             "iot:Connect", 
                             "iot:Receive", 
                             "iot:GetThingShadow", 
                             "iot:DeleteThingShadow", 
                             "iot:UpdateThingShadow"
                             ],
                         "Resource": [
                             "*"
                             ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "greengrass:*"
                            ],
                        "Resource": [
                            "*"
                            ]
                    }
                ]
            }
    response = IOT.create_policy(policyName=name, policyDocument=json.dumps(core_policy_doc))
    return response

def attach_principal_and_policy(name, certs_arn):
    """
        input: policy name
        input: certificate arn
        output: response
    """
    response = IOT.attach_principal_policy(policyName=name, principal=certs_arn)
    return response

def parse_certificate_pem(infile, outfile):
    """
        input: state filename 
        input: cert.pem filename 
    """
    with open(infile) as fp1:
        data = json.load(fp1)
    with open(outfile, 'w') as fp2:
        fp2.write(data['keys_certs']['certificatePem'])

def parse_private_key(infile, outfile):
    """
        input: state filename 
        input: private.key filename 
    """
    with open(infile) as fp:
        data = json.load(fp)
    with open(outfile, 'w') as fp:
        fp.write(data['keys_certs']['keyPair']['PrivateKey'])

def parse_public_key(infile, outfile):
    """
        input: state filename
        input: public.key filename
    """
    with open(infile) as fp:
        data = json.load(fp)
    with open(outfile, 'w') as fp:
        fp.write(data['keys_certs']['keyPair']['PublicKey'])

def parse_config(infile, outfile):
    """
        input: state filename
        input: config.json filename
    """
    with open(infile) as fp:
        data = json.load(fp)
    config_contents = {
                "coreThing" : {
                    "caPath" : "root.ca.pem",
                    "certPath" : data['group']['Name'] + ".cert.pem",
                    "keyPath" : data['group']['Name'] + ".private.key",
                    "thingArn" : data['core_thing']['thingArn'],
                    "iotHost" : data['iot_endpoint']['endpointAddress'],
                    "ggHost" : "greengrass-ats.iot.us-east-1.amazonaws.com",
                    "keepAlive" : 600
                    },
                "runtime" : {
                        "cgroup" : {
                            "useSystemd" : "yes"
                            }
                        },
                "managedRespawn" : False,
                "crypto" : {
                    "principals" : {
                        "SecretsManager" : {
                            "privateKeyPath" : "file:///greengrass/certs/" + data['group']['Name'] + ".private.key"
                            },
                        "IoTCertificate" : {
                             "privateKeyPath" : "file:///greengrass/certs/" + data['group']['Name'] + ".private.key",
                             "certificatePath" : "file:///greengrass/certs/" + data['group']['Name'] + ".cert.pem"
                             }
                        },
                    "caPath" : "file:///greengrass/certs/root.ca.pem"
                    }
                }
    with open(outfile, 'w') as fp:
        json.dump(config_contents, fp, indent=4)

def generate_truststore(group_id):
    """
        input: group id
        output: response
    """
    response = GG.list_group_certificate_authorities(GroupId=group_id)
    return response

def gg_new_deployment(group_id, group_ver_id):
    """
        input: group id
        input: group_ver_id
        output:
    """
    response = GG.create_deployment(
            DeploymentType='NewDeployment',
            GroupId=group_id,
            GroupVersionId=group_ver_id
            )
    return response

def main():
    
    # test area - start
    #print(generate_truststore('2a00068c-7213-4012-9ac6-c2d6892d8216'))
    #print(generate_truststore('205991a0-efd1-4144-82b4-d2613f194897'))
    #print(generate_truststore('0829d503-d2d5-4a23-a077-a905076fd8e5'))
    #exit()
    # test area - end 


    print("Creating thing type")
    edge_device_type = "Edge-Device"
    machine_device_type = "Machine"
    create_thing_type(edge_device_type, "Edge Device")
    create_thing_type(machine_device_type, "devices")

    dev_id = "deviceID"
    dev_name = "edge-test-boto"
    group_name = dev_name
    os.mkdir(dev_id)

    ###
    #   Create Greengrass group, core, certificates, policy
    ###
    #print(check_greengrass_group(group_name))
    if not check_greengrass_group(group_name):
        group = create_greengrass_group(group_name)
        print(group_name +" group created")
        keys_certs = create_certs()
        print(group_name +" certs created")
        #print(keys_certs)
        core_name = group_name + "_core"
        core_thing = create_thing(core_name, edge_device_type)
        print(core_name + " core created")
        attach_thing_and_principal(core_thing['thingName'], keys_certs['certificateArn'])
        print("Principal attached to thing " + core_name)
        policy_name = core_name + "_policy"
        policy = create_policy(policy_name)
        print(policy_name + " policy created")
        attach_principal_and_policy(policy['policyName'], keys_certs['certificateArn'])
        print("Policy attached to the principal " + policy_name)
        core_definition = GG.create_core_definition(
                Name = group_name,
                InitialVersion = {
                    'Cores': [
                        {
                            'CertificateArn': keys_certs['certificateArn'],
                            'Id': core_thing['thingName'],
                            'SyncShadow': False,
                            'ThingArn': core_thing['thingArn']
                        }
                    ]
                }
            )
        group_ver = GG.create_group_version(
                GroupId = group['Id'],
                CoreDefinitionVersionArn=core_definition['LatestVersionArn']
            )
        iot_endpoint = IOT.describe_endpoint(endpointType='iot:Data-ATS')

        state = {
                'group': group,
                'core_thing': core_thing,
                'keys_certs': keys_certs,
                'group_ver': group_ver,
                'core_definition': core_definition,
                'policy': policy,
                'iot_endpoint': iot_endpoint
            }

        core_dir = dev_id + "/" + dev_name
        os.mkdir(core_dir)

        state_file = core_dir + "/" + dev_name + ".json"
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=4)

        certs_dir = core_dir + "/certs"
        os.mkdir(certs_dir)
        
        cert_pem = certs_dir + "/" + group_name + ".cert.pem"
        parse_certificate_pem(state_file, cert_pem)

        private_key = certs_dir + "/" + group_name + ".private.key"
        parse_private_key(state_file, private_key)

        public_key = certs_dir + "/" + group_name + ".public.key"
        parse_public_key(state_file, public_key)

        config_dir = core_dir + "/config"
        os.mkdir(config_dir)

        config_file = config_dir + "/config.json"
        parse_config(state_file, config_file)

        new_deployment = gg_new_deployment(group_ver['Id'], group_ver['Version'])
        print(new_deployment)

    else:
        print(group_name +" already present")

if __name__ == "__main__":
    main()




exit()
