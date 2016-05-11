import phantom.rules as phantom
import json

def detonate_url_cb(action, success, container, results, handle):

    if not success:
        return

    parameter = {}
    
    queue_id = phantom.collect(results, "action_result.data.*.id")
    
    if (queue_id):
        parameter['id'] = queue_id[0]
        
    report_id = phantom.collect(results, "action_result.data.*.report_id")
    
    if (report_id):
        parameter['report_id'] = report_id[0]
    

    phantom.act("get report", parameters=[parameter], assets=["urlquery"])

    return


def on_start(container):

    requestURL = set(phantom.collect(container, 'artifact:*.cef.requestURL'))

    parameters = []

    for url in requestURL:
        parameters.append({"url": url,})

    phantom.act("detonate url", parameters=parameters, assets=["urlquery"], callback=detonate_url_cb)

    return

def on_finish(container, summary):

    return
