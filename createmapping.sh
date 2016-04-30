#! /bin/bash
curl -XPUT localhost:9200/_template/logstash -d '
{           
            "template": "logstash-*",          
               "settings" : {
                 "index" : {
                   "refresh_interval" : "5s"
                 }
               },
               "mappings": {
                 "_default_": {
                   "dynamic": true,
                   "_all" : {"enabled" : true, "omit_norms" : true},
                   "properties": {
                      "@timestamp": {"type": "date", "doc_values" : true},
                      "@version": { "type": "string", "index": "not_analyzed", "doc_values" : true},
                      "offset": {"type": "long"},
                      "ts": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                      "src_ip": {"type":"string", "index":"not_analyzed"},
                      "src_ipv6": {"type":"string", "index":"not_analyzed"},
                      "src_port": {"type":"integer"},
                      "dst_ip": {"type":"string", "index":"not_analyzed"},
                      "dst_ipv6": {"type":"string", "index":"not_analyzed"},
                      "dst_port": {"type":"integer"},
                      "assigned_ip": {"type":"ip", "doc_values" : true},
                      "duration": {"type":"float"},
                      "orig_bytes": {"type":"integer"},
                      "resp_bytes": {"type":"integer"},
                      "conn_state_full": {"type":"string", "index":"not_analyzed"},
                      "missed_bytes": {"type":"integer"},
                      "orig_pkts": {"type":"integer"},
                      "orig_ip_bytes": {"type":"integer"},
                      "resp_pkts": {"type":"integer"},
                      "resp_ip_bytes": {"type":"integer"},
                      "sensorname": {"type":"string", "index":"not_analyzed"},
                      "levelmessage": {"type":"string", "index":"not_analyzed"},
                      "mac": {"type":"string", "index":"not_analyzed"},
                      "lease_time": {"type":"float"},
                      "trans_id": {"type":"integer"},
                      "depth": {"type":"integer"},
                      "analyzers": {"type":"string", "index":"not_analyzed"},
                      "mime_type": {"type":"string", "index":"not_analyzed"},
                      "filename": {"type":"string", "index":"not_analyzed"},
                      "seen_bytes": {"type":"integer"},
                      "total_bytes": {"type":"integer"},
                      "missing_bytes": {"type":"integer"},
                      "overflow_bytes": {"type":"integer"},
                      "extracted": {"type":"string", "index":"not_analyzed"},
                      "query": {"type":"string", "index":"not_analyzed"},
                      "answers": {"type":"string", "index":"not_analyzed"},
                      "TTLs": {"type":"float"},
                      "method": {"type":"string", "index":"not_analyzed"},
                      "host": {"type":"string", "index":"not_analyzed"},
                      "uri": {"type":"string", "index":"not_analyzed"},
                      "referrer": {"type":"string", "index":"not_analyzed"},
                      "user_agent": {"type":"string", "index":"not_analyzed"},
                      "status_code": {"type":"integer"},
                      "note": {"type":"string", "index":"not_analyzed"},
                      "msg": {"type":"string", "index":"not_analyzed"},
                      "sub": {"type":"string", "index":"not_analyzed"},
                      "actions": {"type":"string", "index":"not_analyzed"},
                      "software_type": {"type":"string", "index":"not_analyzed"},
                      "software_name": {"type":"string", "index":"not_analyzed"},
                      "version_major": {"type":"integer"},
                      "version_minor": {"type":"integer"},
                      "version_addl": {"type":"string", "index":"not_analyzed"},
                      "unparsed_version": {"type":"string", "index":"not_analyzed"},
                      "certificate_subject": {"type":"string", "index":"not_analyzed"},
                      "certificate_issuer": {"type":"string", "index":"not_analyzed"},
                      "san_dns": {"type":"string", "index":"not_analyzed"},
                      "san_uri": {"type":"string", "index":"not_analyzed"},
                      "san_email": {"type":"string", "index":"not_analyzed"},
                      "san_ip": {"type":"string", "index":"not_analyzed"},
                      "geoip_src": {
                        "properties": {
                          "ip": {"type": "ip"},
                          "location": {"type": "geo_point"},
                          "latitude": {"type": "double"},
                          "longitude" : {"type": "double"}
                        }
                      },
                      "geoip_dst": {
                        "properties": {
                          "ip": {"type": "ip"},
                          "location": {"type": "geo_point"},
                          "latitude": {"type": "double"},
                          "longitude" : {"type": "double"}
                        }
                      } 
                }
           }
      }  
}'
