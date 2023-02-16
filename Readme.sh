oc delete secret wsse
oc create secret generic wsse   --from-file=./apicast-policy.json   --from-file=./init.lua   --from-file=./wsse.lua
oc rollout latest dc/apicast-staging
#add the following properties in the APIManager yaml definition at the spec.apicast.stagingSpec.customPolicies
#        - name: wsse
#          secretRef:
#            name: wsse
#          version: '0.1'
