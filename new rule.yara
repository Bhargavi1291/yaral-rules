rule mfa_bruteforce_without_response
{
  meta:
     subject = "mfa bruteforce without response"
     description = "None"
     tactic = "Credential Access"
     technique = "Brute Force"
     subtechnique = "Credential Stuffing"
     tool = ""
     datasource = "User Account"
     category = ""
     product = "Okta"
     logsource = "SSO"
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "Medium"
     severity = "Medium"
     falsePositives = "Users having trouble logging in"
     externalSubject = "0"
     externalMITRE = "0"
     version = "1"

  events:
    $e.principal.namespace = "f9_corp_okta"
    $e.metadata.product_event_type = "system.push.send_factor_verify_push"
    $user = $e.principal.user.userid
    $product_log_id = $e.metadata.product_log_id 
 
  match:
    $user over 5m

  condition:
    #product_log_id > 6
}
