rule suspicious_remote_interactive_logon_detcted
{
  meta:
     subject = "suspicious remote interactive logon detcted"
     description = "This rule detects when same user does remote interactive logins into more than three systems within short time interval. Adversaries commonly utilize compromised user credentials to laterally move to other systems on the network, aiming to expand their access and control. Monitoring this behavior helps to identify potential unauthorized lateral movement."
     tactic = "Lateral Movement"
     technique = "Remote Services"
     subtechnique = "T1562.001"
     tool = ""
     datasource = "Logon Session"
     category = ""
     product = ""
     logsource = "Windows Events"
     actor = ""
     malware = ""
     vulnerability = ""
     custom = ""
     confidence = "Low"
     severity = "High"
     falsePositives = "This could be benign when administrator intentionally login into multiple servers."
     externalSubject = "0"
     externalMITRE = "0"
     version = "3"

  events:
        $e.metadata.event_type = "USER_LOGIN"  
        $e.extensions.auth.mechanism = "REMOTE_INTERACTIVE"
        
        
        $e.target.user.userid != "bhargavi"
        $e.target.user.userid != ""
        $e.observer.hostname = $target_hostname
       

     
    
    match:
        $target_user over 1h 

    condition:
      $e
}
