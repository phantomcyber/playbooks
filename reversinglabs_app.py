"""
This playbook runs all the ReversingLabs actions one by one.
"""

import phantom.rules as phantom
import json

def file_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    return


def on_start(incident):

    phantom.act('file reputation', parameters=[ { "hash": "99017f6eebbac24f351415dd410d522d" },
        { "hash": "7896b9b34bdbedbe7bdc6d446ecb09d5" },  
        { "hash": "7896b9b34bdbedbe7bdc6d446ecb09d5" },  
        { "hash": "aaaaaaaaaaaabbbbbbbbbbccccccccc" },  
          { "hash": "74fe8c68d878cc9699a2781be515bb003931ffa2ad21dc0c2c48eb91caba4b44" },  
          { "hash": "8a6af8587adf0e743871ad6b9889428b5f75b86b" },  
            { "hash": "52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c" },  
            { "hash": "4d1740485713a2ab3a4f5822a01f645fe8387f92" },  
              { "hash": "44ac2504a02af84ee142adaa3ea70b868185906f"}
], assets=["reversinglabs_private"], callback=file_reputation_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
