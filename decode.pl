#!/usr/bin/perl
use strict;
use warnings;

use Switch;
use feature 'unicode_strings';
use open ':encoding(UTF-8)';

use constant {
	SWAPS => 500, #number of swaps in random key generation
};

#default options and global variables
my $ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; #alphabet used
my @ALPHABET; #$ALPHA split
my $LEN; #length of $ALPHA
my @CTEXT; #will hold the cipher text (with no invalid characters)
my $CLEN; #length of cipher text
my %NGRAMS; #contains the log probability for ngrams
my $LOGS = "ngrams/english/234gramslog.txt"; #file with ngram logs
my $CLIMB = 5000; #key mutations
my $NONEW = 500; #stale keys before early break
my $TRIES = 20; #random key attempts
my $MINGRAM = 2; #minimum length of ngrams - auto detected
my $MAXGRAM = 3; #maximum length of ngrams - ibid

#generates a random key using the given alphabet
sub randKey {
	my @key = @ALPHABET;
	for (my $i = 0; $i < SWAPS; $i++){ #generates random key by swapping random letters in alphabet
		my $r1 = int(rand($LEN));
		my $r2 = int(rand($LEN));
		my $temp = $key[$r1]; #faster to just swap instead of checking if they are the same
		$key[$r1] = $key[$r2];
		$key[$r2] = $temp;
	}
	return join ("", @key);
}

#finds local best key mutation from random starting key
sub findMax {
	my $key = randKey(); #generates a random starting key
	my $ptext = decode($key, join ("", @CTEXT)); #decrypts cipher text using this key
	my $fitness = fitness($ptext); #finds the fitness of the decrypted cipher text
	for (my $i = 0, my $noNew = 0; $noNew < $NONEW && $i < $CLIMB; $noNew++, $i++){ #noNew breaks early if we are (presumably) at the local maximum
		my $newKey = $key;
		my $r1 = int(rand($LEN)); #mutates key by swapping two random letters in key and seeing if the fitness improves
		my $r2 = int(rand($LEN));
		if ($r1 != $r2){ #dont swap if same letter
			my $temp1 = substr ($newKey, $r1, 1);
			my $temp2 = substr($newKey, $r2, 1);
			substr ($newKey, $r1, 1, $temp2);
			substr ($newKey, $r2, 1, $temp1);
			my $newPtext = $ptext;
			$newPtext =~ s/$temp1/x/g; #fastest way to swap two characters in a string? (faster than redecoding cipher text with new key)
			$newPtext =~ s/$temp2/$temp1/g;
			$newPtext =~ s/x/$temp2/g;
			my $newFitness = fitness($newPtext);
			if ($newFitness > $fitness){ #strictly greater than to save effort and to not reset noNew on a stale key
				$key = $newKey;
				$fitness = $newFitness;
				$ptext = $newPtext;
				$noNew = 0;
			}
		}
	}
	return $key
}

#takes a key and decrypts the cipher text
sub decode {
	my $key = shift;
	my $ctext = shift;
	my @key = split //, $key;
	my %sub;
	for (my $i = 0; $i < $LEN; $i++){ #build hash table from key to decode cipher text
		$sub{$ALPHABET[$i]} = $key[$i];
	}
	my @ptext = ();
	my $letter;
	foreach $letter (split //, $ctext){
		if (defined $sub{$letter}){ #retain any punctuation and other characters not in alphabet (for final result)
			push @ptext, $sub{$letter};
		} else {
			push @ptext, $letter;
		}
	}
	return join ("", @ptext);
}

#calculates the fitness of a piece of text
sub fitness {
	my $text = shift;
	my $fitness = 0;
	for (my $i = 0; $i < $CLEN; $i++){ #get all substrings of various lengths in cipher text and find their log probablility
		for (my $j = $MINGRAM; $j <= $MAXGRAM && ($i + $j) <= $CLEN; $j++){ #$i + $j ensures it doesnt run over the end of the string
			my $str = substr($text, $i, $j);
			if (defined($NGRAMS{$str})){ #just in case the log file doesnt have all ngram permutations of alphabet
				$fitness = $fitness + $NGRAMS{$str};
			} else {
				$fitness = $fitness - 20;
			}
		}
	}
	return $fitness;
}

sub main {
	if ($#ARGV < 0){
		die "usage: perl -CS $0 <decode1> [<decode2> ...]\n\t[-t <# random key tries>]\n\t[-n <break on # stale keys>]\n\t[-c <generate # key mutations>]\n\t[-l <file with log probabilities>]\n\t[-a <language\n\t\t| DN (danish) |\n\t\t| EN (englsih) |\n\t\t| FN (finnish) |\n\t\t| FR (french) |\n\t\t| GN (german) |\n\t\t| IC (icelandic) |\n\t\t| PL (polish) |\n\t\t| RU (russian) |\n\t\t| SP (spanish) |\n\t\t| SW (swedish)|>]\n";
	}
	my @files = ();
	my $logFile = 0;
	my $i;
	for ($i = 0; $i <= $#ARGV; $i++){ #parse command line arguments
		switch ($ARGV[$i]){
			case "-t" { #number of random keys to generate
				$i++;
				$TRIES = $ARGV[$i];
			} case "-n" { #number of stale keys before breaking
				$i++;
				$NONEW = $ARGV[$i];
			} case "-c" { #how many mutations per key
				$i++;
				$CLIMB = $ARGV[$i];
			} case "-l" { #provide a different log file
				$i++;
				$logFile = 1; #make sure changing the language doesnt overwrite the log file
				$LOGS = $ARGV[$i];
			} case "-a" { #use a differnt lanuage - changes alphabet and sets default log file for that language (unless log file is specified)
				$i++;
				switch ($ARGV[$i]){
					case "DN" {
						$ALPHA = join "", $ALPHA, "\N{U+00C6}\N{U+00D8}\N{U+00C5}";
						if (!($logFile)){
							$LOGS = "ngrams/danish/234gramslog.txt";
						}
					} case "EN" {
						#already english
					} case "FN" {
						$ALPHA = join "", $ALPHA, "\N{U+00C4}\N{U+00D6}";
						if (!($logFile)){
							$LOGS = "ngrams/finnish/234gramslog.txt";
						}
					} case "FR" {
						$ALPHA = join "", $ALPHA, "\N{U+00C0}\N{U+00C0}\N{U+00C6}\N{U+00C8}\N{U+00C9}\N{U+00CA}\N{U+00CB}\N{U+00CE}\N{U+00CF}\N{U+00D4}\N{U+0152}\N{U+00D9}\N{U+00DB}\N{U+00DC}\N{U+0178}\N{U+00C7}";
						if (!($logFile)){
							$LOGS = "ngrams/french/234gramslog.txt";
						}
					} case "GN" {
						$ALPHA = join "", $ALPHA, "\N{U+1E9E}\N{U+00C4}\N{U+00D6}\N{U+00DC}";
						if (!($logFile)){
							$LOGS = "ngrams/german/234gramslog.txt";
						}
					} case "IC" {
						$ALPHA = join "", $ALPHA, "\N{U+00C1}\N{U+00C6}\N{U+00C9}\N{U+00CD}\N{U+00D3}\N{U+00D6}\N{U+00DA}\N{U+00DD}\N{U+00D0}\N{U+00DE}";
						if (!($logFile)){
							$LOGS = "ngrams/icelandic/234gramslog.txt";
						}
					} case "PL" {
						$ALPHA = join "", $ALPHA, "\N{U+0104}\N{U+0106}\N{U+0118}\N{U+0141}\N{U+0143}\N{U+00D3}\N{U+015A}\N{U+0179}\N{U+017B}";
						if (!($logFile)){
							$LOGS = "ngrams/polish/234gramslog.txt";
						}
					} case "RU" {
						$ALPHA = "\N{U+0410}\N{U+0411}\N{U+0412}\N{U+0413}\N{U+0414}\N{U+0415}\N{U+0401}\N{U+0416}\N{U+0417}\N{U+0418}\N{U+0419}\N{U+041A}\N{U+041B}\N{U+041C}\N{U+041D}\N{U+041E}\N{U+041F}\N{U+0420}\N{U+0421}\N{U+0422}\N{U+0423}\N{U+0424}\N{U+0425}\N{U+0426}\N{U+0427}\N{U+0428}\N{U+0429}\N{U+042A}\N{U+042B}\N{U+042C}\N{U+042D}\N{U+042E}\N{U+042F}";
						if (!($logFile)){
                                                        $LOGS = "ngrams/russian/234gramslog.txt";
                                                }
					} case "SP" {
						$ALPHA = join "", $ALPHA, "\N{U+00C1}\N{U+00C9}\N{U+00CD}\N{U+00D3}\N{U+00DA}\N{U+00DC}\N{U+00D1}";
						if (!($logFile)){
                                                        $LOGS = "ngrams/spanish/234gramslog.txt";
                                                }
					} case "SW" {
						$ALPHA = join "", $ALPHA, "\N{U+00C4}\N{U+00C5}\N{U+00D6}";
						if (!($logFile)){
                                                        $LOGS = "ngrams/swedish/234gramslog.txt";
                                                }
					} else { #unrecognised language
						die "usage: perl -CS $0 <decode1> [<decode2> ...]\n\t[-t <# random key tries>]\n\t[-n <break on # stale keys>]\n\t[-c <generate # key mutations>]\n\t[-l <file with log probabilities>]\n\t[-a <language\n\t\t| DN (danish) |\n\t\t| EN (englsih) |\n\t\t| FN (finnish) |\n\t\t| FR (french) |\n\t\t| GN (german) |\n\t\t| IC (icelandic) |\n\t\t| PL (polish) |\n\t\t| RU (russian) |\n\t\t| SP (spanish) |\n\t\t| SW (swedish)|>]\n";
					}
				}
			} case "-h" { #print help (usage)
				die "usage: perl -CS $0 <decode1> [<decode2> ...]\n\t[-t <# random key tries>]\n\t[-n <break on # stale keys>]\n\t[-c <generate # key mutations>]\n\t[-l <file with log probabilities>]\n\t[-a <language\n\t\t| DN (danish) |\n\t\t| EN (englsih) |\n\t\t| FN (finnish) |\n\t\t| FR (french) |\n\t\t| GN (german) |\n\t\t| IC (icelandic) |\n\t\t| PL (polish) |\n\t\t| RU (russian) |\n\t\t| SP (spanish) |\n\t\t| SW (swedish)|>]\n";
			} else { #if not a flag add to the list of files to decode
				push @files, $ARGV[$i];
			}
		}
	}
	@ALPHABET = split //, $ALPHA;
	$LEN = length($ALPHA);
	open (my $g, "<", $LOGS) or die "couldnt open log file\n";
	print "building hash table...\n";
	my $line;
	while ($line = <$g>){
		chomp $line;
		my @row = split / /, $line;
		my $lenRow = length($row[0]);	
		if ($lenRow < $MINGRAM){ #auto detect the maximum and minimum ngram lengths
			$MINGRAM = $lenRow;
		} elsif ($lenRow > $MAXGRAM){
			$MAXGRAM = $lenRow;
		}
		$NGRAMS{$row[0]} = $row[1];
	}
	close $g;
	foreach my $path (@files){ #decrypt each file in turn
		open (my $f, "<", $path) or die "couldnt open file\n";
		my $message = "";
		print "reading file...\n";
		while ($line = <$f>){
			chomp $line;
			$message = join("", $message, $line);
		}
		close $f;
		$message = uc($message); 
		@CTEXT = split //, $message; #keep message with punctuation for later printing
		my $letter;
		foreach $letter (@CTEXT){
			if (index($ALPHA, $letter) == -1){
				$letter = "";
			}
		}
		my $cText = join ("", @CTEXT);
		@CTEXT = split //, $cText; #make sure cipher text only has valid characters
		$CLEN = length($cText);
		srand(time());
		print "starting decryption of...\n$message\n\n";
		for ($i = 0; $i < $TRIES; $i++){ #try TRIES times to find the correct key
			my $key = findMax(); #get local max key
			my $ptext = decode($key, $message); #decode version of cipher text with punctuation
			print "Key: $key\nPlain text:\n$ptext\n\n";
		}
	}
}

main();
