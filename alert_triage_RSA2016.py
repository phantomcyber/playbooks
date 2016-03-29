"""Orchestrates enrichment and protective actions on via assets like Splunk, CarbonBlack, Tanium, etc."""
import phantom.utils as utils
import phantom.rules as phantom
import json


# ------------------------------------------------------------------------
# If the infected endpoint is a VM,
#        'snapshot vm' using vSphere for forensics
# ------------------------------------------------------------------------
def list_vms_cb(action, success, container, results, handle):
    if not success:
        phantom.debug('list vms action FAILED')
        return

    # ------------------------------------------------------------------------
    # ==> GENERIC ACTION #9:  snapshot the infected endpoint if its a VM 
    # ------------------------------------------------------------------------
    sourceAddress = set(phantom.collect(container, 'artifact:*.cef.sourceAddress'))
    
    success_results = phantom.parse_success(results)
    for vm_info in success_results:
        if 'ip' in vm_info:# if the VM is running, it will have an IP
            if vm_info['ip'] in sourceAddress: #if the IP address of the VM is the attacked IP
                phantom.debug('=====>> CALLING "snapshot vm" since the infected PC is a VM')
                # uncomment this line below to actually do the snapshot action
                #phantom.act('snapshot vm', parameters=[{'vmx_path':vm_info['vmx_path'],'download': False}])
            else:
                phantom.debug('This ip: '+','.join(sourceAddress)+' is NOT a running VM instance')

    return

# ------------------------------------------------------------------------
# if domain is not a well known domain, sinkhole the domain via 
#        'block domain' on OpenDNS Umbrella
# ------------------------------------------------------------------------
def domain_reputation_cb(action, success, container, results, handle):
    if not success:
        phantom.debug('domain reputation action FAILED')
        return

    status = phantom.collect(results,'action_result.status')
    domain = phantom.collect(results, 'action_result.parameter.domain')
    domain_status = phantom.collect(results, 'action_result.summary.domain_status')
    phantom.debug('domain_reputation data: status: '+ str(status) + ' domain: '+str(domain)+' domain_status: '+str(domain_status))

    # ------------------------------------------------------------------------
    # ==> GENERIC ACTION #10:  sinkhole or block the domain using OpenDNS Umbrella
    # ------------------------------------------------------------------------
    parameters = []
    for i in range(0, len(status)):
        if (status[i].lower()=='success') and (domain_status[i].lower() == 'unknown'):
            parameters.append({"domain": domain[i]})
        
    #phantom.debug(parameters)
    
    if parameters:
        phantom.debug('=====>> CALLING "block domain on OpenDNSUmbrella" is domain is UNKNOWN!')
        # uncomment this line below to actually do the bocking action
        #phantom.act("block domain", parameters=parameters, assets=["opendns_umbrella"])

    return

# ------------------------------------------------------------------------
# if the hash has > 3 vendors detecting it as malicious, 
#        'terminate process' using Tanium on infected endpoint
# ------------------------------------------------------------------------
def file_reputation_cb(action, success, container, results, handle):
    if not success:
        phantom.debug('file reputation action FAILED')
        return
    
    status = phantom.collect(results, 'action_result.status')
    hash = phantom.collect(results, 'action_result.parameter.hash')
    score = phantom.collect(results, 'action_result.summary.positives')
    phantom.debug('file_reputation data: status: '+ status + ' hash: '+hash+' score: '+str(score))

    # ------------------------------------------------------------------------
    # ==> CONMTAINMENT ACTION #11: terminate the running malicious process on end points
    # ------------------------------------------------------------------------
    
    cefs = phantom.collect(container, 'artifact:*.cef.')
    # the logic below is to make sure we are getting the fileName from the same artifact
    # that has the fileHash and sourceAddress i.e. fileName is of the fileHash found on 
    # the infected endpoint, or else you could get fileHash from an artifact and fileName 
    # from a different artifact etc. 
    triplets={}
    for cef in cefs:
        if all (k in cef for k in ("fileHash","fileName", "sourceAddress")): 
            triplets[cef['fileHash'].upper()] = cef
    
    parameters=[]
    for i in range(0, len(status)):
        if (status[i].lower()=='success') and (score[i] > 3) and (hash[i] in triplets):
            phantom.debug(hash)
            cef_obj = triplets.get(hash)
            parameters.append({"ip_hostname": cef_obj['sourceAddress'],"name": cef_obj['fileName']})
    
    
    #phantom.debug(parameters)
    
    if parameters:
        phantom.debug('=====>> CALLING "terminate process via Tanium" if score is > 3')
        # uncomment this line below to actually do the terminate action
        #phantom.act("terminate process", parameters=parameters, assets=["tanium"])

    return

# ------------------------------------------------------------------------
# if the 'c2c IP' is not in North America region
#        'block ip' using PaloAlto Networks FW
# ------------------------------------------------------------------------
def whois_ip_cb(action, success, container, results, handle):
    if not success:
        phantom.debug('whois ip action FAILED')
        return
    
    status = phantom.collect(results, 'action_result.status')
    ip = phantom.collect(results, 'action_result.parameter.ip')
    country = phantom.collect(results, 'action_result.summary.country_code')
    phantom.debug('whois_ip data: status: '+ status + ' ip: '+ip+' country: '+country)
    
    # ------------------------------------------------------------------------
    # ==> CONMTAINMENT ACTION #12: block the c2c IP on PAN firewalls
    # ------------------------------------------------------------------------
    parameters=[]
    if (status.lower()=='success') and (country.upper() == 'RU'):
        parameters.append({"ip": ip})

    #phantom.debug(parameters)
    
    if parameters:
        phantom.debug('=====>> CALLING "block ip" on PAN firewall')
        # uncomment this line below to actually do the bocking action
        #phantom.act("block ip", parameters=parameters, assets=["pan"])

    return

# ------------------------------------------------------------------------
# if the infected machine is in 'ACCOUNTS' department and is a Desktop
#        'quarantine device' using CrabonBlack
# ------------------------------------------------------------------------
def get_system_info_cb(action, success, container, results, handle):

    if not success:
        phantom.debug('get system info action FAILED')
        return

    status = phantom.collect(results, 'action_result.status')
    ip = phantom.collect(results, 'action_result.parameter.ip_hostname')
    comp_name = phantom.collect(results, 'action_result.data.*.computer_dns_name')
    os_type = phantom.collect(results, 'action_result.data.*.os_type')
    phantom.debug('get_system_info data: status: '+ status + ' ip: '+ip+' os_type: '+str(os_type)+' comp_name: '+comp_name)
    
    # ------------------------------------------------------------------------
    # ==> CONMTAINMENT ACTION #13: quarantine the endpoints
    # ------------------------------------------------------------------------
    parameters=[]
    if (success.lower()=='success') and (os_type == 1) and ('accounts' in comp_name.lower()):
        parameters.append({"ip_hostname": ip})        
                        
    #phantom.debug(parameters)
    
    if parameters:
        phantom.debug('=====>> CALLING "quarantine device on CarbonBlock" FROM "get_system_info callback" =======')
        # uncomment this line below to actually do the quarantine action
        #phantom.act("quarantine device", parameters=parameters, assets=["carbonblack"])

    return

def hunt_file_cb(action, success, container, results, handle):

    if not success:
        return

    status = phantom.collect(results, 'action_result.status')
    hash = phantom.collect(results, 'action_result.parameter.hash')
    machines = phantom.collect(results, 'action_result.data.*.binary.results.*.endpoint.*')
    signed = phantom.collect(results, 'action_result.data.*.binary.results.*.signed')
    phantom.debug('hunt_file data: status: '+ status + ' hash: '+hash+' signed: '+signed+' machines: '+str(machines))
    
    # ------------------------------------------------------------------------
    # ==> PREVENTION ACTION #14: block the file hash on the endpoints
    # ------------------------------------------------------------------------
    parameters=[]
    if (success == 'success') and (signed.lower() != 'signed'):
        for machine in machines:
            host = machine.rsplit('|',1)[0]
            parameters.append({"ip_hostname":host,"hash":hash})
    elif signed.lower() == 'signed':
        phantom.debug('Will not block the file '+hash+' on: ['+str(machines)+'] since its Signed')
        return
    
    #phantom.debug(parameters)
    
    if parameters:
        phantom.debug('=====>> CALLING "block hash" on endpoints via SRP policies =======')
        phantom.act("block hash", parameters=parameters, assets=["domainctrl1"])
    
    return

def on_start(container):
    
    # get IPs to which Malware was talking to
    c2c_ips = set(phantom.collect(container, 'artifact:*.cef.destinationAddress'))
    
    # get hashes of the malware detected
    fileHash = set(phantom.collect(container, 'artifact:*.cef.fileHash'))

    # get URL from where the malware was downloaded
    sourceURLs = set(phantom.collect(container, 'artifact:*.cef.requestURL'))
    
    # get IP address of the infected machine
    infected_ips = set(phantom.collect(container, 'artifact:*.cef.sourceAddress'))
    
    # get file names for the malware
    fileNames = set(phantom.collect(container, 'artifact:*.cef.fileName'))
    #return

    # ------------------------------------------------------------------------
    # ==> INVESTITAGE ACTION #1:  "list vms" to see if the infected PC is a VM
    # ------------------------------------------------------------------------
    parameters = []
    
    phantom.act("list vms", parameters=parameters, assets=["vmwarevsphere"], callback=list_vms_cb)

    # ------------------------------------------------------------------------
    # ==> INVESTITAGE ACTION #2:  "domain reputation" to identify the domain 
    #     from where malware was dowloaded
    # ------------------------------------------------------------------------
    parameters = []

    for url in sourceURLs:
        domain = url
        if 'http:' in url:
            domain = url.split('//', 1)[1].split('/', 1)[0]
        parameters.append({"domain": domain,})
    
    phantom.act("domain reputation", parameters=parameters, assets=["opendns_investigate"], callback=domain_reputation_cb)
    
    # ------------------------------------------------------------------------
    # ==> INVESTITAGE ACTION #3:  "file reputation" ... how bad the file is
    # ------------------------------------------------------------------------
    parameters = []
    
    for hash in fileHash:
        parameters.append({"hash": hash,})

    phantom.act("file reputation", parameters=parameters, assets=["reversinglabs_private"], callback=file_reputation_cb)
    
    # ------------------------------------------------------------------------
    # ==> INVESTITAGE ACTION #4:  "whois ip" about the C2C server
    # ------------------------------------------------------------------------
    parameters = []

    for ip in c2c_ips:
        parameters.append({"ip": ip,})

    phantom.act("whois ip", parameters=parameters, assets=["whois"], callback=whois_ip_cb)

    # ------------------------------------------------------------------------
    # ==> INVESTITAGE ACTION #5:  "get systme info" using CarbonBlack
    # ------------------------------------------------------------------------
    parameters = []

    for ip_hostname in infected_ips:
        parameters.append({"ip_hostname": ip_hostname,})
        
    phantom.act("get system info", parameters=parameters, assets=["carbonblack"], callback=get_system_info_cb)
    
    # ------------------------------------------------------------------------
    # ==> INVESTITAGE ACTION #6:  "geolocate ip" using MaxMind
    # ------------------------------------------------------------------------
    parameters = []

    for ip in c2c_ips:
        parameters.append({"ip": ip,})

    phantom.act("geolocate ip", parameters=parameters, assets=["maxmind"])

    # ------------------------------------------------------------------------
    # ==> INVESTITAGE ACTION #7:  "hunt file" using CarbonBlack
    #        find the machines that have the same malicious hash
    # ------------------------------------------------------------------------
    parameters = []
    
    # uncomment these lines for a test query against a known hash
    #fileHash = []
    #fileHash.append('8ac253bb517fa0da92d04040ca7e771b')
    for hash in fileHash:
        parameters.append({"hash": hash,"type": "binary"})
    
    phantom.act("hunt file", parameters=parameters, assets=["carbonblack"], callback=hunt_file_cb)

    # ------------------------------------------------------------------------
    # ==> INVESTITAGE ACTION #8:  "query" Splunk to see which all machines have 
    #        seen this file name and download URL
    # ------------------------------------------------------------------------
    parameters = []
    
    parameters.append({"query": 'malware_download_detected '+' '.join(fileNames) +' '.join(sourceURLs)})
    
    phantom.act("run query", parameters=parameters, assets=["splunk_entr"])

    return

def on_finish(container, summary):
                   
    # parameters = []
    # parameters.append({
    #     "from": "admin@somecorp.com",
    #     "to": "user@somecorp.com",
    #     "subject": "Phantom Automation Completed",
    #     "body": summary,
    #     "attachments": "",
    # })
    # phantom.act("send email", parameters=parameters, assets=["smtp"])

    return

