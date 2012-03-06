#!/usr/bin/perl
# {{{ use
use strict;
use warnings;
use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION = 1;
# }}}

my %opts;
getopts('doehi:p:n:s:', \%opts);

# {{{ usage
sub HELP_MESSAGE {
  my $h = shift;
  print $h "Usage: $0 [options] [SSID]\n";
  print "  -o\t\tDump the profile to STDOUT\n";
  print "  -e\t\tEdit the NetCFG profile after generating it\n";
  print "  -h\t\tSet the network as hidden\n";
  print "  -i <iface>\tInterface to scan on (wlan0)\n";
  print "  -p <enc>\tSelect authentication mechanism (WEP|WPA)\n";
  print "  -n <name>\tSet the name of the connction\n";
  print "  -s <scan>\tInstead of scanning, parse this scan\n";
}

sub VERSION_MESSAGE {
  my $h = shift;
  print $h "wifi-connect version 0.2\n";
}
# }}}

use constant {
  USERNAME => 2,
  PASSWORD => 1,
};

# bitflags, 1 = password, 2 = username
my $authentication = 0;
my $encryption = undef;
my $essid = shift @ARGV;

# {{{ Network selection
if (not defined $essid) {
  my $interface = defined $opts{'i'} ? $opts{'i'} : 'wlan0';
  my @networks = ();
  my $ignoreNextGc = 0;
  my @scan = ();
  if (defined $opts{'s'}) {
    open my $h, $opts{'s'} or die "Failed to read scanfile: $!\n";
    @scan = <$h>;
    close $h;
  } else {
    @scan = `iwlist $interface scan`;
  }

  my $network = undef;
  foreach (@scan) {
    if (/Cell \d+ - Address: /) {
      push @networks, $network if defined $network and defined $network->{'essid'};
      $network = {
        'authentication' => 0,
        'encryption' => 0
      };
      $ignoreNextGc = 0;
    } elsif (/quality=(\d+)\/70/i) {
      $network->{'quality'} = 100 * $1/70;
      $network->{'quality'} = 100 if $1 > 70;
    } elsif (/ESSID:"(.+)"/) {
      $network->{'essid'} = $1;
    } elsif (/Encryption key:(on|off)/) {
      $network->{'authentication'} = $network->{'authentication'} | PASSWORD if $1 eq 'on';
    } elsif (/IE: WPA Version \d/) {
      # if for WPA+WPA2
      if ($network->{'encryption'}) {
        $ignoreNextGc = 1;
      } else {
        $network->{'encryption'} = 'WPA';
      }
    } elsif (/IE: IEEE 802.11i\/WPA2 Version \d/) {
      $network->{'encryption'} = 'WPA2' if $network->{'encryption'} !~ /WPA Enterprise/;
    } elsif (/Group Cipher : (.*)$/) {
      if ($ignoreNextGc) {
        $ignoreNextGc = 0;
        next;
      }

      my $gc = $1;
      if ($network->{'encryption'} =~ /WPA2/) {
        $network->{'encryption'} .= '+' . $gc;
      } else {
        $network->{'encryption'} .= '-' . $gc;
      }
      $network->{'encryption'} = 'WPA2' if $network->{'encryption'} eq 'WPA2+CCMP';
      $network->{'encryption'} = 'WPA' if $network->{'encryption'} eq 'WPA-TKIP';
      $network->{'encryption'} = 'WPA-AES' if $network->{'encryption'} eq 'WPA-CCMP';
    } elsif (/Authentication Suites \(\d+\) : 802\.1x/) {
      # WPA Enterprise
      $network->{'encryption'} = 'WPA Enterprise';
      $network->{'authentication'} = USERNAME | PASSWORD;
    }
  }
  push @networks, $network if defined $network and defined $network->{'essid'};

  if (@networks <= 1) {
    print "Very few networks were found, perhaps you should run this script as root?\n";
  }

  @networks = sort {$b->{'quality'} <=> $a->{'quality'}} @networks;

  sub quality {
    my $network = shift;
    return '+' if $network->{'quality'} >= 80;
    return '-' if $network->{'quality'} <= 30;
    return '=';
  }

  for (my $i = 0; $i < @networks; $i++) {
    my $n = $networks[$i];
    printf "%02d: %-30s [%1s] (%s, %d%%)\n", $i + 1, $n->{'essid'}, quality($n), $n->{'encryption'} || 'Open', $n->{'quality'};
  }

  my $selection = undef;
  while (not defined $selection) {
    print "Which network would you like to connect to? ";
    $selection = <STDIN>;
    $selection =~ /(\d+)/;
    $selection = $1; #will be undef if no match
    $selection = undef if $selection > @networks;
  }

  printf "You chose network #%d: %s. Good choice!\n", $selection, $networks[$selection - 1]->{'essid'};
  my $chosen = $networks[$selection - 1];

  $essid = $chosen->{'essid'};
  $authentication = $chosen->{'authentication'};
  $encryption = 'wpa' if $chosen->{'encryption'} =~ /WPA/;
  $encryption = 'wep' if $chosen->{'encryption'} =~ /WEP/;
  #TODO: PAP vs MD5 for TTLS
  $encryption = "wpae" if $chosen->{'encryption'} =~ /WPA Enterprise/;
}
# }}}

if (defined $opts{'p'}) {
  if ($opts{'p'} eq "WPA") { $authentication = PASSWORD; $encryption = "wpa"; }
  if ($opts{'p'} eq "WEP") { $authentication = PASSWORD; $encryption = "wep"; }
  #TODO: PEAP vs TTLS (PAP vs MD5)
  if ($opts{'p'} =~ /WPAE/) { $authentication = USERNAME | PASSWORD; $encryption = "wpae"; }
}

# {{{ Prompt for username and password
my $username = undef;
my $password = undef;
if ($authentication & USERNAME) {
  print "Enter username: ";
  $username = <STDIN>;
  chomp $username;
}
if ($authentication & PASSWORD) {
  print "Enter password: ";
  $password = <STDIN>;
  chomp $password;
}

# WEP also allows passphrases
if ($encryption eq 'wep') {
  $password = 's:' . $password if (length $password != 10 && length $password != 26);
}
# }}}

my $saveas = $opts{'n'};
# {{{ Connection name
if (not defined $saveas and not defined $opts{'o'}) {
  my $proposal = $essid;
  $proposal =~ s/\s+/-/g;
  $proposal =~ s/[^\w\-]//g;
  printf "Save this network as [%s]: ", $proposal;
  $saveas = <STDIN>;
  chomp $saveas;

  $saveas = $proposal if $saveas =~ /^\s*$/;
}
# }}}

if ($encryption eq "wpae") {
  print "What inner encryption should I use for the WPA Enterprise?\n";
  print "Common choices are PEAP or TTLS [PEAP]: ";
  my $e = <STDIN>;
  chomp $e;
  $e = 'PEAP' if $e =~ /^\s*$/;
  $encryption .= '-' . uc($e);
}

my $h = undef;
$h = *STDOUT if $opts{'o'};
open $h, "> /etc/network.d/$saveas" or die "Couldn't open /etc/network.d/$saveas for writing: $!\n" if not defined $h;

printf $h "CONNECTION='wireless'\n";
printf $h "DESCRIPTION='Connection to %s network %s'\n", $encryption || 'open', $essid;
printf $h "INTERFACE='wlan0'\n";
printf $h "SECURITY='%s'\n", $encryption ? ($encryption =~ /wpae/ ? 'wpa-configsection' : $encryption) : 'none';

if ($encryption =~ /wpae-(\w+)/) {
  my $type = $1;
  # {{{ CONFIGSECTION
  print $h "CONFIGSECTION='\n";
  # Basics
  printf $h "\tssid=\"%s\"\n", $essid;
  printf $h "\tkey_mgmt=WPA-EAP\n";

  # Allow only TKIP and CCMP
  printf $h "\tgroup=TKIP CCMP\n";
  printf $h "\tpairwise=TKIP CCMP\n";

  # PEAP vs TTLS
  printf $h "\teap=%s\n", $type;

  # Authentication
  printf $h "\tidentity=\"%s\"\n", $username;
  printf $h "\tpassword=\"%s\"\n", $password;

  # TODO: PAP vs MD5 for TTLS
  printf $h "\tphase1=\"peaplabel=0\"'\n", if $type eq 'PEAP';
  printf $h "\tphase2=\"auth=%s\"'\n", $type eq 'PEAP' ? 'MSCHAPV2' : 'PAP';
} else {
  printf $h "ESSID='%s'\n", $essid;
  printf $h "KEY='%s'\n", $password if $encryption;
  # }}}
}

printf $h "IP='dhcp'\n";
printf $h "HIDDEN=yes\n" if $opts{'h'};

close $h if not defined $opts{'o'};

exec "vim", "/etc/network.d/$saveas" if $opts{'e'};
print "Connection successfully saved as $saveas\n" if not defined $opts{'o'};
exit 0;
