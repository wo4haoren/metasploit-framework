#
# $Id$
# $Revision$
#

module Msf

    ###
    # msf5 > load alias
    # [*] Successfully loaded plugin: alias
    # msf5 > load caller
    # [*] Caller plugin loaded.
    # [*] Successfully loaded plugin: caller
    # msf5 > alias -f cert "call -a auxiliary/scanner/http/cert RHOSTS=" 
    # msf5 > cert 127.0.0.1 ######## -> Call the specified auxiliary by one line command.
    
    # [*] Calling auxiliary/scanner/http/cert RHOSTS=127.0.0.1
    
    # [*] 127.0.0.1:443         - 127.0.0.1 - 'schneider.keebler.org' : '2019-02-22 22:49:09 UTC' - '2023-02-21 22:49:09 UTC'
    # [*] 127.0.0.1:443         - Scanned 1 of 1 hosts (100% complete)
    
    # msf5 >
    ###
  class Plugin::ThreadTest < Msf::Plugin
    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher
        def name
          "Caller"
        end
    
        def commands
          {
            "call" => "call an auxiliary module"
          }
        end
    
        def cmd_caller_help
            print(@@caller_opts.usage)
        end


        @@caller_opts = Rex::Parser::Arguments.new(
          "-a"  => [ true,  "The (aux|post) module to call. "             ],
          "-h"  => [ false, "Example : call -a post/windows/gather/smart_hashdump session=12"])


        def cmd_call(*args)
          extra = nil
          mod = nil
          opts = {}

          @@caller_opts.parse(args) do |opt, idx, val|
            case opt
              when "-a"
                mod = val
              when "-h"
                cmd_caller_help
                return false
              else
                extra = "#{extra} #{val}"
              end
            end

          unless extra.to_s.strip.empty?
            extra = extra.gsub(/=\s+/,"=").strip
            print_line
            print_status("Calling #{mod} #{extra}")

            if m = framework.modules.create(mod)
                Msf::Simple::Auxiliary.run_simple(m,{"OptionStr" => extra,'RunAsJob' => false,'LocalOutput' => driver.output})
            else
                print_error("Module #{mod} not found!")
            end
            print_line
          else
            cmd_caller_help
          end
        end

        def help(opt_parser = nil, msg = 'Usage: call auxiliary OPTIONS')
            print_line(msg)
          end
      end   
    
      def initialize(framework, opts)
        super
        add_console_dispatcher(ConsoleCommandDispatcher)
        print_status("Caller plugin loaded.")
      end
    
      def cleanup
        remove_console_dispatcher('Caller')
      end
    
      def name
        "caller"
      end
      
      def desc
        "Call and run auxiliary with just one line command. "
      end
    
    protected
    end
    
    end
    