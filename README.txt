Etherbat — Ethernet topology discovery

  What is Etherbat?

   Etherbat performs Ethernet topology discovery between 3 hosts: the machine
   running Etherbat and two other devices.

     * Are they in the same switch?
     * Are they in three separate switches?
     * Which host is closer to local machine?

       — these are example questions answered by Etherbat.

   Etherbat could be described as layer 2 equivalent of traceroute.

   No manageable switches nor extra software on remote hosts is required.

  Use cases

    Locating hosts

   Attacker: "Where is that internal database server located?"

   Admin: "I know there is an internal attack executing right now, but where
   it originates from?"

    Network mapping

   Admin: "I want to have detailed map of the network, but I don't want to
   track every cable physically. The boss doesn't want to buy manageable
   switches."

   Auditor: "Let's check if the network documentation describes real network
   structure."

   Note: The map of the network could be created by repeatedly executing
   Etherbat with different host combinations and joining gathered results.
   Etherbat won't do this automatically.

  Features

     * Ethernet topology discovery between 3 hosts
     * 8 different topologies recognized
     * No manageable switches required:
          * reduces costs for network owner,
          * no need to get access to them for an attacker.
     * No extra software on remote hosts is neccessary.
     * Error detection and correction decreases probability of false result.
     * Different switch types supported.
     * Mostly clean and (I hope) easy to read OO Ruby code, GPL.

  Limitations

   Warning! Etherbat was tested only on wired network. It won't work on
   wireless. Also, it could give incorrect results:

     * on networks with hubs and/or some (broken) switch types and software
       bridges (i.e. Linux bridge used by many wireless Access Points)
     * on some enterprise switches due to delayed MAC learning process (may
       be fixed in future versions by increasing timeouts)
     * when hosts being tested are generating traffic during test and it's
       not detected by Etherbat
     * in some situations if Windows machines are being tested (in these
       cases Etherbat displays warning message)
     * probably in other cases due to not yet discovered bugs

  How does it work?

   Etherbat uses MAC spoofing to create invalid paths in the network, probes
   how it changed by injecting specially crafted ARP requests and checks for
   replies or absence of them. Afterwards it makes the network return to
   normal state.

  Requirements

     * Ruby (1.8.4 tested)
     * Libnet (1.1.2.1 tested)
     * Libpcap 0.9.3 - 0.9.8. Previous versions will not work as
       pcap_setdirection() function is needed (as far as I know this function
       is implemented only on Linux and *BSD). Version 1.0.0 has a bug which
       causes Etherbat to work incorrectly.
     * Glib 2.0 (2.12.4 tested)
     * Libnet, Libpcap and Glib headers and c toolchain for compilation

   Etherbat is written in interpreted language, but needs to launch external
   processes for frame injection and sniffing. Those are C programs which
   needs to be compiled.

   Etherbat source code is released under the terms of GPLv2 license.

  Compilation and installation

   Optionally alter instalation path at the beginning of Makefile. If you
   want to link Libnet and Libpcap libraries to be linked dynamically (you
   should do this if your distribution ships shared versions of these
   libraries like Debian does) execute:

    $ make

   Otherwise, you need to specify libpcap.a and/or libnet.a files to link
   statically with. For example if both are placed in /usr/lib/ you should
   type:

    $ make PCAP_STATIC=/usr/lib/libpcap.a LIBNET_STATIC=/usr/lib/libnet.a

   After successful compilation, if you are using sudo issue:

    $ sudo make install

   or if you are using su:

    $ su -c "make install"

   Note that the installation is required for program to run correctly. You
   can uninstall it with:

    $ sudo make uninstall

   or if you are using su:

    $ su -c "make uninstall"

  Usage

   Etherbat requires two IP addresses as arguments. It will display how local
   machine and hosts with those addresses are connected in form of ASCII
   diagram. Here is example output (for those of you typing ^fscreenshot in
   Firefox ;-) )

 # etherbat 10.0.0.1 10.0.0.2
 0: 10.0.0.10 (00:12:1b:d8:a9:86)
 1: 10.0.0.1 (00:0f:18:ce:5f:29)
 2: 10.0.0.2 (00:26:b4:c5:8c:12)

  1   2 0
   \ /  |
    *-~-*

   Use -h to see list of possible options.

   To understand what does all of this ASCII art mean and how to use some
   options read tests description.

  LLTD

   I've planned to write whitepaper about Ethernet topology discovery, but
   some time after I had finished Etherbat 1.0.0 I've found this document. It
   describes similiar technique invented by three Microsoft guys (Richard
   Black, Austin Donnelly and Cedric Fournet) and presented in 2004 on IEEE
   conference. Reading it will give you almost everything needed to
   understand how Etherbat works.

   Recently I've found this technique was implemented in Windows Vista as
   Link Layer Topology Discovery (LLTD) and used in Network Map feature.

   When I was writing Etherbat I was unaware of Microsoft researchers work.
   General idea of LLTD and the technique used by Etherbat is the same, but
   there are some differences.

   The main difference is that LLTD is far more complex (as it's distibuted
   system) and has more features, ie. it provides extensions for QoS tests,
   integrates anti-DoS functions. And last but not least — every host being
   located could provide his own icon to appear on the map (I wonder when
   LLTD themes will show on the Internet ;-)

   LLTD                    Etherbat                   Notes                   
                                                      It is possible to       
                                                      create application      
                                                      which invokes Etherbat  
   LLTD maps entire        Etherbat discovers         repeatedly for          
   network.                topology between 3 hosts.  different host          
                                                      combinations and joins  
                                                      results somehow to      
                                                      build the map. Also see 
                                                      TODO.                   
                                                      LLTD authors consider   
                                                      support for devices     
   LLTD requires all hosts                            without responders (see 
   to have responders      Etherbat doesn't need any  section 5, paragraph    
   installed to be placed  extra software on remote   "Uncooperative hosts"   
   on the map.             hosts.                     of mentioned paper),    
                                                      but as far as I know    
                                                      it's not implemented    
                                                      (yet?).                 
                           Etherbat works on Linux                            
                           and should work on *BSD    
   LLTD enumerator (the    systems without            
   tool coordinating       modifications (but wasn't  
   topology discovery) is  tested). Porting to other   
   available for Windows   platforms should be        
   Vista only.             straightforward as         
                           majority of code is        
                           written in Ruby.           
   LLTD enumerator source  Etherbat code is released  LLTD responder source   
   code is not available.  under GPL license.         code is available to    
                                                      download.               
   LLTD uses special MAC                                                      
   address family which    Etherbat impersonates host 
   doesn't collide with    being tested, so it may    
   MAC addresses used in   temporarily cause traffic   
   the network — normal    destined to this host to   
   traffic is not          be lost.
   affected.               
   LLTD operation is not   Etherbat is sensitive to                           
   disturbed by other host traffic generated by hosts  
   transmissions.          being tested.              
   LLTD correctly detect                                                      
   hubs and wireless                                  
   stuff; topology         
   detected is generally   Etherbat doesn't support
   more accurate. Authors  hubs and wireless.          
   presented formal proof  
   of algorithm            
   correctness and         
   completeness.           

  TODO 

     * HIGH PRIORITY: Three remote hosts mode. It is more resistant to
       different switch types and better handles Windows machines.
     * One host mode — fingerprint path from local host to remote machine
       (taking advantage of different switch types behavior and some other
       tricks).
     * Support for other asymmetric protocols and techniques, i.e. IPv6 (NDP
       in place of ARP), IPX, ARP+L3/4 (no need for asymmetric ARP — poison
       ARP cache, send spoofed ping and wait for reply; can be used with TCP
       or UDP).
     * Are all recognized topologies correct? In particular direct
       connections on ASCII diagrams may not be direct in case of some switch
       types.
     * Batch mode to test many host combinations in one invocation (for use
       by third party mapping apps).
     * Increase performance under high pps (optimize frame handling, use bpf
       filters to ignore irrelevant frames).
     * Optimize tests to generate less traffic.

  FAQ

    1. Can I use Etherbat to map remote network which is somewhere in the
       Internet?

       Etherbat is a layer 2 tool, uses MAC spoofing and ARP protocol. This
       kind of stuff won't be forwarded by routers.
       The only possibility is too use some kind of Ethernet over IP
       tunneling (note: when the tunnel is not 100% transparent it may impact
       result).

    2. What is there are hubs (Ethernet repeaters) in the network?

       Depending on hub placement Etherbat will work good, refuse to work or
       work badly and display incorrect results.

    3. Etherbat doesn't display all switches.

       If there are multiple switches in the line between hosts under test
       they are displayed as 0, 1 or more switches. See symbols description
       at the end of tests description.

  Author/contact

   This software was written by me, Paweł Pokrywka. You can find my email
   address at:
   https://www.pawelpokrywka.com
