#!/usr/bin/perl

#Created by Daniel Lohrey - z5015215
#Created for cs6441 Something Awesome project
#All options are set as constants, with some other options as commented

use strict;
use warnings;
use threads;

use constant {
	CLIMB => 10000, #iterations of key mutation
	NONEW => 500, #quit if no more changes in key
	TRIES => 3, #number of random keys generated per thread
	THREADS => 3, #number of thread to create (excluding main thread with also shares the load)
	SWAPS => 500, #number of swaps in random key generation (shouldnt need to change)
	MINGRAM => 2, #min ngram length in log file given below - may need to change if changing log file
	MAXGRAM => 3, #max ngram length in log file - ibid
	LEN => 26, #length of alphabet - may need to change if using different alphabet (such as for decrypting in another language)
};

#global variables, all are read only
my @CTEXT; #will hold the cipher text
my %NGRAMS; #contains the log probability for ngrams
my $CLEN; #length of the cipher text

my $LOGS = "/home/daniel/cs6441/ngrams/english/23gramslog.txt"; #file constaining log probabilities of ngrams (digrams and trigrams)
#my $LOGS = "/home/daniel/cs6441/ngrams/english/234gramslog.txt"; #also contains quadgrams

#finds local best key mutation from random starting key - run by each thread
sub findMax {
	my $ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; #current alphabet - can change to alphabet for other languages (or to include other characters that may be present in log file)
        my @ALPHABET = split //, $ALPHA;
	for (my $i = 0; $i < TRIES; $i++){ #generates TRIES random keys to attempt to find solution (in succession)
		#start randKey - generate a random key permutation
		my @key = @ALPHABET;
		my $j;
		my $k;
		for ($j = 0; $j < SWAPS; $j++){
			my $r1 = int(rand(LEN));
			my $r2 = int(rand(LEN));
			my $temp = $key[$r1]; #doesnt care if theyre the same place - too slow to check every time (1/26 * swap < 26 * compare)
			$key[$r1] = $key[$r2];
			$key[$r2] = $temp;
		}
		my $key = join ("", @key);
		#end randKey - key in $key
		#decode - decode given cipher text using key
		my %sub;
		for ($j = 0; $j < LEN; $j++){ #generate hash to translate using key
			$sub{$ALPHABET[$j]} = $key[$j];
		}
		my @ptext = ();
		my $letter;
		my $ctext = join ("", @CTEXT); #need to get local copy of cipher text to decode #could probably take out the join and have to global be the string (doesnt happen often though)
		foreach $letter (split //, $ctext){ #redundant split - could just have a dictionary to copy into (unless copying strings is much faster?)
			#if (defined $sub{$letter}){ #dont have to check valid characters since all invalid characters are taken out
				push @ptext, $sub{$letter};
			#} else {
			#	push @ptext, $letter;
			#}
		}
		my $ptext = join ("", @ptext);
		#end decode - ptext in $ptext
		#fitness - calculates the fitness of the decoded text
		my $fitness = 0;
		my $str;
		for ($j = 0; $j < $CLEN; $j++){
			for (my $k = MINGRAM; $k <= MAXGRAM && ($j + $k) <= $CLEN; $k++){
				$str = substr($ptext, $j, $k);
				#if (defined($NGRAMS{$str})){ #dont have to check if an ngram is in log file since it has all ngrams and invalid characters are removed
					$fitness = $fitness + $NGRAMS{$str};
				#} else {
				#	$fitness = $fitness - 20;
				#}
			}
		}
		#end fitness - fitness in $fitness
		#findMax - finds local maximum fitness of text by swapping random letters in key
		for (my $m = 0, my $noNew = 0; $noNew < NONEW && $m < CLIMB; $noNew++, $m++){ #noNew breaks loop if we arent getting any new, better keys (presumably at the local maximum) - means we dont have to have redundant checks when we are already finished
			my $newKey = $key;
			my $r1 = int(rand(LEN));
			my $r2 = int(rand(LEN));
			if ($r1 != $r2){ #dont do anything if theyre the same character cause that would be a lot of effort
				my $temp1 = substr ($newKey, $r1, 1);
				my $temp2 = substr($newKey, $r2, 1);
				substr ($newKey, $r1, 1, $temp2);
				substr ($newKey, $r2, 1, $temp1);
				my $newPtext = $ptext;
				$newPtext =~ s/$temp1/x/g; #possibily the fastest way to swap two characters in a string? (faster than re-decoding entire string with new key)
				$newPtext =~ s/$temp2/$temp1/g;
				$newPtext =~ s/x/$temp2/g;
				#start fitness - get fitness of the new key
				my $newFitness = 0;
				for ($j = 0; $j < $CLEN; $j++){
					for ($k = MINGRAM; $k <= MAXGRAM && ($j + $k) <= $CLEN; $k++){
						$str = substr($newPtext, $j, $k);
						#if (defined($NGRAMS{$str})){
							$newFitness = $newFitness + $NGRAMS{$str};
						#} else {
						#	#$newFitness = $newFitness - 20;
						#}
					}
				}
				#end fitness - fitness in $newFitness
				if ($newFitness > $fitness){ #only strictly greater than to save effort and to not reset noNew on a stale key
					$key = $newKey;
					$fitness = $newFitness;
					$ptext = $newPtext;
					$noNew = 0;
				}
			}
		}
		#end findMax - print result
		print "Key: $key\nPlain text:\n$ptext\n\n";
	}
	return;
}

sub main {
	if (!defined($ARGV[0])){
		print "need file to decode\n";
		return;
	}
	my $path = $ARGV[0]; #onl one file at a time
	open (my $f, "<", $path) or die "couldnt open file\n";
	my $line;
	my $message = "";
	print "reading file...\n";
	while ($line = <$f>){
		chomp $line;
		$message = join("", $message, $line);
	}
	close $f;
	$message = uc($message);
	@CTEXT = split //, $message;
	my $letter;
	my $ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; #can change alphabet if desired
	my @cText = ();
	foreach $letter (@CTEXT){ #take out all characters that arent in alphabet
		if (index($ALPHA, $letter) > -1){
			push @cText, $letter;
		}
	}
	my $cText = join ("", @cText);
	@CTEXT = split //, $cText;
	$CLEN = length($cText);
	open (my $g, "<", $LOGS) or die "couldnt open log file\n";
	print "building hash table...\n";
	while ($line = <$g>){ #log file should contain all ngrams for all characters in alphabet
		chomp $line;
		my @row = split / /, $line;
		$NGRAMS{$row[0]} = $row[1];
	}
	close $g;
	srand(time());
	for (my $i = 0; $i < THREADS; $i++){ #start some new threads to get through a large amount of thries quickly
		print "starting new thread...\n";
		srand(time());
		my $thr = threads->create('findMax');
		if ($thr == undef){
			print "thread creation failed\n";
		}
	}
	findMax(); #do some tries in the main thread
	$_->join() for threads->list(); #wait for threads to finish
	return;
}

main();
