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
        print_status("Check if target OS is supported...")
        print_status("Target OS is " + sysinfo['OS'])

        if sysinfo['OS'] !~ /Windows (XP|Vista|7|8|10)/
          print_error("Only supported on Windows \(XP|Vista|7|8|10\)")
          return
        end
                                                                                         
        print_good("Loading extapi... ")
        client.core.use("extapi")

        root = 'root\SecurityCenter2'
        if sysinfo['OS'] =~ /Windows XP/
            root = 'root\SecurityCenter'
        end

        begin
            result = client.extapi.wmi.query("select displayName, productState from antivirusproduct",root)
            rescue RuntimeError
                raise
            return
        end
  
        if result.count == 0 
            print_status("No AV found by wmi query.")
            return
        end

        result.each { |k,v|
            if "#{k}" == "values"
                    print_error("#{v.count} AV found!")
                    v.each { |a,b|
                        isEnable = sprintf("%06x", b).upcase[2,2].to_i < 10 ? "Disabled" : "Enabled"
                        isUpToDate = sprintf("%06x", b).upcase[4,2] == "00" ? "UpToDate" : "not UpToDate" 
                        if isEnable == "Enabled" 
                            print_error("#{a} is #{isEnable} and the signature database is #{isUpToDate}")
                        else
                            print_status("#{a} is #{isEnable} and the signature database is #{isUpToDate}") 
                        end
                    }
            end
        }
    end
end