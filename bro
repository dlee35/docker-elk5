################################################################################
# Copyright 2014-2015 Jose Ortiz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################
TS %{NUMBER:ts}
UID %{DATA:uid}
ORIGH %{IP:src_ip}
ORIGP %{INT:src_port}
RESPH %{IP:dst_ip}
RESPP %{INT:dst_port}
BROHEADER %{TS}\t%{UID}\t%{ORIGH}\t%{ORIGP}\t%{RESPH}\t%{RESPP}
BROAPPSTATS %{TS}\t%{DATA:ts_delta}\t%{DATA:app}\t%{DATA:uniq_hosts}\t%{DATA:hits}\t%{DATA:bytes}
BROCAPTURELOSS %{TS}\t%{DATA:ts_delta}\t%{DATA:peer}\t%{DATA:gaps}\t%{DATA:acks}\t%{DATA:percent_loss}
BROCOMMUNICATION %{TS}\t%{DATA:peer}\t%{DATA:src_name}\t%{DATA:connected_peer_desc}\t%{DATA:connected_peer_addr}\t%{DATA:connected_peer_port}\t%{DATA:level}\t%{GREEDYDATA:msg}
BROCONN %{NUMBER:ts}\t%{DATA:uid}\t%{IP:src_ip}\t%{INT:src_port}\t%{IP:dst_ip}\t%{INT:dst_port}\t%{DATA:proto}\t%{DATA:service}\t%{DATA:duration}\t%{DATA:orig_bytes}\t%{DATA:resp_bytes}\t%{DATA:conn_state}\t%{DATA:local_orig}\t%{DATA:local_resp}\t%{DATA:missed_bytes}\t%{DATA:history}\t%{DATA:orig_pkts}\t%{DATA:orig_ip_bytes}\t%{DATA:resp_pkts}\t%{DATA:resp_ip_bytes}\t%{GREEDYDATA:tunnel_parents}\t%{DATA:orig_cc}\t%{DATA:resp_cc}\t%{GREEDYDATA:sensorname}
BRODHCP %{BROHEADER}\t%{DATA:mac}\t%{IP:assigned_ip>}\t%{DATA:lease_time}\t%{GREEDYDATA:trans_id}
BRODNP3 %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:fc_request}\t%{DATA:fc_reply}\t%{DATA:iin}
BRODNS %{BROHEADER}\t%{DATA:proto}\t%{DATA:trans_id}\t%{DATA:query}\t%{DATA:qclass}\t%{DATA:qclass_name}\t%{DATA:qtype}\t%{DATA:qtype_name}\t%{DATA:rcode}\t%{DATA:rcode_name}\t%{DATA:AA}\t%{DATA:TC}\t%{DATA:RD}\t%{DATA:RA}\t%{DATA:Z}\t%{DATA:answers}\t%{DATA:TTLs}\t%{DATA:rejected}
BRODPD %{BROHEADER}\t%{DATA:proto}\t%{DATA:analyzer}\t%{GREEDYDATA:failure_reason}
BROFILES %{TS}\t%{DATA:fuid}\t%{DATA:src_ip}\t%{DATA:dst_ip}\t%{DATA:uid}\t%{DATA:source}\t%{DATA:depth}\t%{DATA:analyzers}\t%{DATA:mime_type}\t%{DATA:filename}\t%{DATA:duration}\t%{DATA:local_orig}\t%{DATA:is_orig}\t%{DATA:seen_bytes}\t%{DATA:total_bytes}\t%{DATA:missing_bytes}\t%{DATA:overflow_bytes}\t%{DATA:timedout}\t%{DATA:parent_fuid}\t%{DATA:md5}\t%{DATA:sha1}\t%{DATA:sha256}\t%{DATA:extracted}
BROFTP %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:user}\t%{DATA:password}\t%{DATA:command}\t%{DATA:arg}\t%{DATA:mime_type}\t%{DATA:file_size}\t%{DATA:reply_code}\t%{DATA:reply_msg}\t%{DATA:data_channel}\t%{DATA:fuid}
BROHTTP %{BROHEADER}\t%{DATA:trans_depth}\t%{DATA:method}\t%{DATA:host}\t%{DATA:uri}\t%{DATA:referrer}\t%{DATA:user_agent}\t%{DATA:request_body_len}\t%{DATA:response_body_len}\t%{DATA:status_code}\t%{DATA:status_msg}\t%{DATA:info_code}\t%{DATA:info_msg}\t%{DATA:filename}\t%{DATA:http_tags}\t%{DATA:username}\t%{DATA:password}\t%{DATA:proxied}\t%{DATA:orig_fuids}\t%{DATA:orig_mime_types}\t%{DATA:resp_fuids}\t%{GREEDYDATA:resp_mime_types}
BROINTEL %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:fuid}\t%{DATA:file_mime_type}\t%{DATA:file_desc}\t%{DATA:seen_indicator}\t%{DATA:seen_indicator_type}\t%{DATA:seen_where}\t%{DATA:sources}
BROIRC %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:nick}\t%{DATA:user}\t%{DATA:command}\t%{DATA:value}\t%{DATA:addl}\t%{DATA:dcc_file_name}\t%{DATA:dcc_file_size}\t%{DATA:dcc_mime_type}\t%{DATA:fuid}
BROKNOWNCERTS %{TS}\t%{DATA:host}\t%{DATA:port_num}\t%{DATA:subject}\t%{DATA:issuer_subject}\t%{GREEDYDATA:serial}
BROKNOWNHOSTS %{TS}\t%{DATA:host}
BROKNOWNSERVICES %{TS}\t%{DATA:host}\t%{DATA:port_num}\t%{DATA:port_proto}\t%{GREEDYDATA:service}
BROMODBUS %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:func}\t%{DATA:exception}
BRONOTICE %{BROHEADER}\t%{DATA:fuid}\t%{DATA:file_mime_type}\t%{DATA:%file_desc}\t%{DATA:proto}\t%{DATA:note}\t%{DATA:msg}\t%{DATA:sub}\t%{DATA:src}\t%{DATA:dst}\t%{DATA:p}\t%{DATA:n}\t%{DATA:peer_descr}\t%{DATA:actions}\t%{DATA:suppress_for}\t%{DATA:dropped}\t%{DATA:remote_location_country_code}\t%{DATA:remote_location_region}\t%{DATA:remote_location_city}\t%{DATA:remote_location_latitude}\t%{GREEDYDATA:remote_location_longitude}
BRORADIUS %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:username}\t%{DATA:mac}\t%{DATA:remote_ip}\t%{DATA:connect_info}\t%{DATA:result}\t%{DATA:logged}
BROREPORTER %{TS}\t%{DATA:level}\t%{DATA:message}\t%{DATA:location}
BROSMTP %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:trans_depth}\t%{DATA:helo}\t%{DATA:mailfrom}\t%{DATA:rcptto}\t%{DATA:date}\t%{DATA:from}\t%{DATA:to}\t%{DATA:reply_to}\t%{DATA:msg_id}\t%{DATA:in_reply_to}\t%{DATA:subject}\t%{DATA:x_originating_ip}\t%{DATA:first_received}\t%{DATA:second_received}\t%{DATA:last_reply}\t%{DATA:path}\t%{DATA:user_agent}\t%{DATA:tls}\t%{DATA:fuids}\t%{DATA:is_webmail}
BROSNMP %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:duration}\t%{DATA:version}\t%{DATA:community}\t%{DATA:get_requests}\t%{DATA:get_bulk_requests}\t%{DATA:get_responses}\t%{DATA:set_requests}\t%{DATA:display_string}\t%{DATA:up_since}
BROSIGNATURES %{TS}\t%{DATA:src_addr}\t%{DATA:src_port}\t%{DATA:dst_addr}\t%{DATA:dst_port}\t%{DATA:note}\t%{DATA:sig_id}\t%{DATA:event_msg}\t%{DATA:sub_msg}\t%{DATA:sig_count}\t%{DATA:host_count}
BROSOCKS %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:version}\t%{DATA:user}\t%{DATA:status}\t%{DATA:request_host}\t%{DATA:request_name}\t%{DATA:request_p}\t%{DATA:bound_host}\t%{DATA:bound_name}\t%{DATA:bound_p}
BROSOFTWARE %{TS}\t%{DATA:src_ip}\t%{DATA:src_port}\t%{DATA:software_type}\t%{DATA:software_name}\t%{DATA:version_major}\t%{DATA:version_minor}\t%{DATA:version_minor2}\t%{DATA:version_minor3}\t%{DATA:version_addl}\t%{GREEDYDATA:unparsed_version}
BROSSH %{BROHEADER}\t%{DATA:status}\t%{DATA:direction}\t%{DATA:client}\t%{DATA:server}\t%{DATA:remote_location_country_code}\t%{DATA:remote_location_region}\t%{DATA:remote_location_city}\t%{DATA:remote_location_latitude}\t%{GREEDYDATA:remote_location_longitude}
BROSSL %{BROHEADER}\t%{DATA:version}\t%{DATA:cipher}\t%{DATA:curve}\t%{DATA:server_name}\t%{DATA:session_id}\t%{DATA:last_alert}\t%{DATA:established}\t%{DATA:cert_chain_fuids}\t%{DATA:client_cert_chain_fuids}\t%{DATA:subject}\t%{DATA:issuer}\t%{DATA:client_subject}\t%{DATA:client_issuer}\t%{GREEDYDATA:validation_status}
BROSYSLOG %{TS}\t%{UID}\t%{DATA:id}\t%{DATA:proto}\t%{DATA:facility}\t%{DATA:severity}\t%{DATA:message}
BROTRACEROUTE %{TS}\t%{DATA:src}\t%{DATA:dst}\t%{DATA:proto}
BROTUNNEL %{BROHEADER}\t%{DATA:tunnel_type}\t%{DATA:action}
BROWEIRD %{BROHEADER}\t%{DATA:name}\t%{DATA:addl}\t%{DATA:notice}\t%{GREEDYDATA:peer}
BROX509 %{TS}\t%{DATA:id}\t%{DATA:certificate_version}\t%{DATA:certificate_serial}\t%{DATA:certificate_subject}\t%{DATA:certificate_issuer}\t%{DATA:certificate_not_valid_before}\t%{DATA:certificate_not_valid_after}\t%{DATA:certificate_key_alg}\t%{DATA:certificate_sig_alg}\t%{DATA:certificate_key_type}\t%{DATA:certificate_key_length}\t%{DATA:certificate_exponent}\t%{DATA:certificate_curve}\t%{DATA:san_dns}\t%{DATA:san_uri}\t%{DATA:san_email}\t%{DATA:san_ip}\t%{DATA:basic_constraints_ca}\t%{DATA:basic_constraints_path_len}
BROUNIFIED %{TS}\t%{DATA:src_ip}\t%{DATA:src_port}\t%{DATA:dst_ip}\t%{DATA:dst_port}\t%{DATA:sensor_id}\t%{DATA:signature_id}\t%{DATA:signature}\t%{DATA:generator_id}\t%{DATA:generator}\t%{DATA:signature_revision}\t%{DATA:classification_id}\t%{DATA:classification}\t%{DATA:priority_id}\t%{DATA:event_id}\t%{GREEDYDATA:packet}
