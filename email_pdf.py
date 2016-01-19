"""
This playbook allows you to detonate a file and send you an email with the results.
Set up an IMAP ingestion asset that polls an email account, and set this playbook to active, 
and it will automatically grab the attached files from the email out of the vault and 
detonate, then send you an email result link.  Be sure to change the to and from email accounts
below under phantom.act('send email').

If multiple artifacts are generated (ie, there are multiple attachments) it should
detonate all attachments and send you an email for each result.
NOTE: PLEASE substitute the email_to and email_from variables to VALID VALUES.

Phantom minimum version 1.0.354
"""
import phantom.rules as phantom
import json
import pprint


def send_email_cb(action, success, email, results, handle):

    if not success:
        phantom.debug("Error sending email.\n{}".format(json.dumps(results)))
        return

    return

def detonate_file_cb(action, success, email, results, handle):
    collectkey = 'collect_data' + str(email['current_rule_run_id'])
    if not success:
        phantom.debug("Error running detonate action.\n{}".format(json.dumps(results)))
        return

    # grab just the results url from the threatgrid return data, perhaps send the entire results dict
    # later as an email attachment?
    #result_url = results[0]['action_results'][0]['summary']['results_url']
    # get the app run ID, and use it as a key to the dictionary we build with results
    app_run_id = results[0]['app_run_id']
    collected_results, collected_vault_items, container_owner = phantom.get_data(collectkey, clear_data=False)
    collected_results[app_run_id] = dict()
    collected_results[app_run_id]['asset'] = results[0]['asset']
    collected_results[app_run_id]['message'] = results[0]['message']
    collected_results[app_run_id]['summary'] = results[0]['summary']
    collected_results[app_run_id]['detonate_summary'] =  results[0]['action_results'][0]['summary']
    phantom.save_data([collected_results, collected_vault_items, container_owner], key=collectkey)

    return


def on_start(email):
    #
    #phantom.debug('Email container data:\n {}\n\n'.format(email))
    email_to = "email_to@my_enterprise.com"
    email_from = "email_from@myenterprise.com"
    smtp_asset = "smtp"
    # these keys are used to save persistent data across the playbook,
    # they must be unique by rule run ID, otherwise its possible the data 
    # could be clobbered in another playbook running at the same time
    setupkey = 'setup_data' + str(email['current_rule_run_id'])
    collectkey = 'collect_data' + str(email['current_rule_run_id'])
    phantom.save_data([email_to, email_from, smtp_asset], key=setupkey)
    #
    collected_results = dict()
    collected_vault_items = dict()
    container_owner = "None"
    container_url = phantom.get_base_url() + 'container/' + str(email['id'])
    ##
    # we needed to get the vault_id for the email attachment to be detonated and pass that to the detonate action
    # so we use phantom.collect to grab the cef field (cs6) where we place the vault_id on the artifact
    vaultid = phantom.collect(email, 'artifact:*.cef.cs6', scope='new')
    #
    if len(vaultid) > 0:  # we have at least one item to process
        # lets grab the owner of the container and make it something useful if blank
        if email['owner'] == '':
            container_owner = 'None'
        else:
            container_owner = email['owner']
        phantom.debug('url: {}'.format(phantom.get_base_url()))
        email_body = "\nStarted file detonations on container_id: {} - Owner: {}\nURL: {}\nvault_item_info:\n".format(email['id'], container_owner, container_url)
        for vault_item in vaultid:
            vaultinfo = phantom.get_vault_item_info(vault_item)
            for vault_item_info in vaultinfo:
                collected_vault_items[vault_item] = vault_item_info
                email_body = email_body + pprint.pformat(vault_item_info, indent=4) + '\n'
            phantom.act('detonate file', parameters=[{'vault_id':vault_item}], assets=["threatgrid"], callback=detonate_file_cb)
        email_subject = "Running: Detonating files from ingest"
        # save modified data
        phantom.save_data([collected_results, collected_vault_items, container_owner], key=collectkey)
        # send email
        phantom.act('send email', parameters=[{ "from" : email_from,  "to" : email_to,  "subject" : email_subject,  "body" : email_body }], assets=[smtp_asset], callback=send_email_cb)
    else: # no artifacts run on
        phantom.debug('No artifacts to process, ending on_start without running any actions. \n{}'.format(email))

    return

def on_finish(email, summary):
    setupkey = 'setup_data' + str(email['current_rule_run_id'])
    collectkey = 'collect_data' + str(email['current_rule_run_id'])
    email_to, email_from, smtp_asset = phantom.get_data(setupkey, clear_data=True)
    container_url = phantom.get_base_url() + 'container/' + str(email['id'])
    # calling get_summary to find out if we actually had anything we acted on
    getsummary = phantom.get_summary()
    #phantom.debug('Get summary: {}'.format(getsummary))
    #
    if len(getsummary['result']) > 0: # we have processed at least one item in on_start
        collected_results, collected_vault_items, container_owner = phantom.get_data(collectkey, clear_data=True)
        # finalize the vault item info and add to email
        for vaultid in collected_vault_items.keys():
            vaultinfo = phantom.get_vault_item_info(vaultid)
            for app_run_id, datavalues in collected_results.iteritems():
                #phantom.debug('iterate collected results: \napprunid: {}\n\ndatavals: {}'.format(app_run_id, datavalues))
                if datavalues['detonate_summary']['target'] == vaultid:
                    collected_results[app_run_id]['vault_info'] = vaultinfo
        if len(collected_results) < (len(getsummary['result'])-2): # subtracting actions that arent counted as detonations
            collected_results['message'] = "Unexpected: Collected Results: {} is less than actions run: {}".format(len(collected_results), (len(getsummary['result'])-2))
        # send summary email
        email_subject = "Results: Ingest file detonatation"
        email_body = '\nPhantom Container ID: {} - Owner: {}\nURL: {}\nReturned results by app_run_id:\n{}'.format(email['id'], container_owner, container_url, pprint.pformat(collected_results, indent=4))
        phantom.act('send email', parameters=[{ "from" : email_from,  "to" : email_to,  "subject" : email_subject,  "body" : email_body }], assets=[smtp_asset], callback=send_email_cb)
        phantom.debug("Summary: " + pprint.pformat(summary, indent=4))
    else: # no artifacts run on
        phantom.debug('No artifacts, sending abort email.')
        email_subject = "Results: No artifacts to run, aborting"
        email_body = '\nPhantom Container ID: {}\nURL: {} \nSummary:\n{}'.format(email['id'],container_url,summary)
        phantom.act('send email', parameters=[{ "from" : email_from,  "to" : email_to,  "subject" : email_subject,  "body" : email_body }], assets=[smtp_asset], callback=send_email_cb)
    return
