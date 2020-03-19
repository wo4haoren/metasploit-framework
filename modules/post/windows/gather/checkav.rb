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
  
        vendor="none"
        state=0
  
        result.each { |k,v| 
            if "#{k}" == "values"
                vendor="#{v[0][0]}"
                state="#{v[0][1]}"
            end
        }
  
        out = "#{vendor} is"
        if sprintf("%06x", state).upcase[2,2].to_i < 10
            out = out + " disabled "
        else
            out = out + " enabled "
        end
  
        if sprintf("%06x", state).upcase[4,2] == "00"
            out = out + "and signature databae is UpToDate !"
        else
            out = out + "and signature database is not UpToDate !"
        end
  
        print_error(out)
    end
end