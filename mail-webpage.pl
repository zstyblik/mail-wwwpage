#!/usr/bin/perl
# 2012/Jun/01 @ Zdenek Styblik <stybla@no-spam.turnovfree.net>
# Desc: parse e-mail from STDIN, fetch content and mail it back
# Use % perldoc mail-webpage.pl ; to read documentation
use strict;
use warnings;
use v5.10;

use lib '/var/lib/postfix/mail-webpage/';

use GPGmod;
use LWP::UserAgent;
use Mail::Sendmail;
use MIME::Base64;
use MIME::Entity;
use MIME::Parser;
use POSIX qw(strftime);

# Variables
my $debug = 0;
my $home_dir = '/var/lib/postfix/mail-webpage/';
my $tmp_dir = $home_dir . "/tmp/";
## SMTP settings
my $my_user = "test";
my $my_domain = "inf-gate-host.vm.zeratul.czf";
my $my_email = sprintf("%s@%s", $my_user, $my_domain);
my $my_subject = "";
my $my_smtp = "";
### Plain-text email validation
my $disable_plaintext = 1;
my $file_users = "";
my $mail_validity = 0;
my $mail_validity_min = 5;
## LWP settings
my $max_wwwpage_size = 2097152;
my @protocols_forbidden = qw(file mail);
my @proxy_schemes = qw//; # qw(http https ftp)
my $proxy_url = ""; # http://localhost:8000/
## GPG settings
my $gpg_homedir = $home_dir . "/.gpg/";
my $gpg_passphrase = "123456789012345";
my $gpg_my_keyid = "CEB62607";
##

# Desc: create LWP::UA instance and fetch WWW content
# $url: URL to fetch
# $method: GET || POST method
# @returns: qw/ret_code, LWP::UA instance/
# @returns: qw/ret_code, undef/ on error
sub get_wwwpage
{
	my $url = shift || "";
	my $method = shift || "GET";
	if (!$url || $url eq "") {
		# "Empty URL given."
		return (-1, undef);
	}
	if ($url !~ /^(ht|f)tp(s?):\/\//) {
		# "URL must be 'http://' or 'https://', '%s' given."
		return (-2, undef);
	}
	if (!$method || $method eq "") {
		# "No method given."
		return (-3, undef);
	}
	if ($method ne "POST" && $method ne "GET") {
		# "Method '%s' is invalid."
		return (-4, undef);
	}
	# Create a user agent object
	use LWP::UserAgent;
	my $ua = LWP::UserAgent->new;
	if (!$ua) {
		die("Failed to initialize LWP::UserAgent: ".$!);
	}
	$ua->agent("MyApp/0.1 ");
	$ua->protocols_forbidden(\@protocols_forbidden);
	$ua->max_size($max_wwwpage_size);
	if (@proxy_schemes && $proxy_url) {
		$ua->proxy(\@proxy_schemes, $proxy_url);
	} # if (@proxy_schemes && $proxy_url)

	# Create a request
	my $req = HTTP::Request->new($method => $url);
	if (!$req) {
		die("Failed to create HTTP::Request.");
	}

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);
	if (!$res) {
		die("HTTP::Response is gone???");
	}

  # Check the outcome of the response
	if ($res->is_success) {
		return ($res->code, $res);
	} else {
			return ($res->code, $res);
	}
} # sub get_wwwpage

# 1] get e-mail from STDIN
my $email_txt = "";
for my $line (<STDIN>) {
	$email_txt.=$line;
}
# 2] create <somekind of email instance>
my $mime_parser = MIME::Parser->new;
die "Unable to create MIME::Parser: ".$! unless $mime_parser;
$mime_parser->output_dir($tmp_dir);
$mime_parser->decode_bodies(0);

my $mime_entity_in = $mime_parser->parse_data($email_txt);
die "Unable to create MIME::Entity - in: ".$! unless $mime_entity_in;

my @mail_body = split(/\n/, $mime_entity_in->stringify_body());

# 4] check whether body is PGP encrypted
my $gpg = GPGmod->new(
	homedir => $gpg_homedir,
	debug => $debug,
);
if (!$gpg) {
	die("Failed to init GPG ".$!);
} elsif ($gpg->error()) {
	die("GPG returned errror: ".$gpg->error());
}

my $gpg_rcpt_keyid = [];
my $mail_encrypted = 0;
foreach (@mail_body) {
	chomp($_);
	if ($_ =~ /^\s*$/) {
		next;
	}
	if ($_ =~ /\bBEGIN PGP SIGNED MESSAGE\b/) {
		$mail_encrypted = 1;
		last;
	}
	if ($_ =~ /\bBEGIN PGP MESSAGE\b/) {
		$mail_encrypted = 2;
		last;
	}
}

my $email_from = "";
if ($mail_encrypted == 1) {
	if ($debug > 0) {
		printf STDERR "It's signed!\n";
	}
	my $verify = $gpg->verify($mime_entity_in->stringify_body());
	if (!$verify || !@$verify[0]) {
		printf STDERR "GPG sign verification failed: %s.\n", $!;
		exit(1);
	}
	if (!@$verify[0]->{'key_id'} || @$verify[0]->{'ok'} != 1) {
		if (@$verify[0]->{'ok'}) {
			printf STDERR "GPG verify status is '%s', expected '1'.",
				@$verify[0]->{'ok'};
		}
		printf STDERR "GPG sign verification failed.\n";
		exit(1);
	}
	if (!@$verify[0]->{'key_id'}) {
		printf STDERR "key_id is not set!";
	} else {
		my $sigd = $gpg->list_sig();
		my $key_found = 0;
		foreach (@$sigd) {
			if (!$_->{'key_id'}) {
				next;
			} # if (!$_->{'key_id'})
			my $key_id_part = substr($_->{'key_id'}, -8);
			if ($key_id_part eq @$verify[0]->{'key_id'}) {
				push(@$gpg_rcpt_keyid, $key_id_part);
				$key_found = 1;
				last;
			} # if ($key_id_part eq ... )
		} # foreach (@$sigd)
		if ($key_found == 0) {
			my $error_msg = sprintf("Key ID '%s' is not known.\n",
				@$verify[0]->{'key_id'});
			die($error_msg);
		} # if ($key_found == 0)
	}
	@mail_body = split(/\n/, $mime_entity_in->stringify_body());
} elsif ($mail_encrypted == 2) {
	if ($debug > 0) {
		printf STDERR "It's encrypted!\n";
	}
	my $decrypted = $gpg->decrypt_verify(
		$gpg_passphrase,
		$mime_entity_in->stringify_body(),
	);
	if ($decrypted->{'ok'} == 0) {
		printf STDERR "Decryption has failed: %s\n", $gpg->error();
		exit(1);
	}
	my %dec_keys = $decrypted->{'keys'};
	my $kc = 0;
	foreach (keys %dec_keys) {
		push(@$gpg_rcpt_keyid, $decrypted->{'keys'}[$_]);
		$kc++;
	}
	if ($kc == 0) {
		printf STDERR "No decryption keys found. Nothing to decrypt with.\n";
		exit(1);
	}
	@mail_body = split(/\n/, $decrypted->{'text'});
} else {
	# 3] check for its validity - subject, data, from, to etc.
	# From, Return-Path, X-Original-To, Delivered-To, To, Date, Message-ID, Subject
	if ($debug > 0) {
		printf STDERR "It's a plain-text.\n";
	}

	if ($disable_plaintext > 0) {
		printf STDERR "Plain-text e-mails are disabled.\n";
		exit(0);
	}

	my $sender_valid = 0;
	if ($file_users) {
		open(FH_USERS, '<', $file_users)
			or die("Unable to open '".$file_users."'.");
		for my $allowed_user (<FH_USERS>) {
			chomp($allowed_user);
			if ($allowed_user =~ /^\s*$/) {
				next;
			}
			if ($mime_entity_in->header("From") =~ /\b${allowed_user}\b/) {
				$email_from = $allowed_user;
				$sender_valid = 1;
				$mail_validity++;
				last;
			}
		} # for my $user_email
		close(FH_USERS);
	} # if ($file_users)
	## - Return-Path
	my $rpath = $mime_entity_in->header("Return-Path");
	$rpath =~ s/<//;
	$rpath =~ s/>//;
	if ($rpath =~ /\b${email_from}\b/) {
		$mail_validity++;
	}
	## - To
	if ($mime_entity_in->header("To") eq $my_email) {
		$mail_validity++;
	}
	## - Delivered-To
	if ($mime_entity_in->header("To") eq
		$mime_entity_in->header("Delivered-To")) {
		$mail_validity++;
	}
	## - X-Original-To
	if ($mime_entity_in->header("X-Original-To") eq $my_user
		|| $mime_entity_in->header("X-Original-To") eq $my_email) {
		$mail_validity++;
	}

	## - Date
	my $today = strftime "%a, %e %b %Y", gmtime;
	if ($mime_entity_in->header("Date") =~ /^${today}/) {
		$mail_validity++;
	}
	## - Message-ID ~ probably not useable
	## - Subject
	my $subject_valid = 0;
	if ($mime_entity_in->header("Subject") eq $my_subject) {
		$subject_valid = 1;
		$mail_validity++;
	}

	if ($sender_valid == 0 || $subject_valid == 0) {
		printf STDERR "Mail doesn't seem to be valid.\n";
		printf STDERR "Sender or Subject don't match; %i/%i.\n", $sender_valid,
			$subject_valid;
		exit(1);
	}
	if ($mail_validity < $mail_validity_min) {
		printf STDERR "Mail doesn't seem to be valid; points %i.\n", $mail_validity;
		exit(1);
	}
}

# 5] check e-mail body for what to do
# +
# 6] fetch page via LWP check the code, resp. errors
if (!$email_from) {
	$email_from = $mime_entity_in->head->get("From");
}

my $mail_message = "";
my $attachments = "";
my $file_counter = 0;
my $boundary = sprintf("====%s====", time().int(rand()));
my $line_count = @mail_body;
for (my $i = 0; $i < $line_count; $i++) {
	chomp($mail_body[$i]);
	if ($mail_body[$i] =~ /^\s*$/) {
		next;
	}
	if ($mail_encrypted == 1
		&& $mail_body[$i] =~ /\bBEGIN PGP SIGNED MESSAGE\b/) {
		next;
	}
	if ($mail_encrypted == 1 && $mail_body[$i] =~ /^Hash: /) {
		next;
	}
	if ($mail_encrypted == 1 && $mail_body[$i] =~ /\bBEGIN PGP SIGNATURE\b/) {
		while ($mail_body[$i] !~ /\bEND PGP SIGNATURE\b/ && ($i + 1) < $line_count) {
			$i++;
			next;
		}
		$i++;
		next;
	}
	if ($mail_body[$i] =~ /^GET .+/i || $mail_body[$i] =~ /^POST .+/i) {
		my @arr_tmp = split(/ /, $mail_body[$i]);
		my $url = "";
		if ($arr_tmp[1]) {
			$url = $arr_tmp[1];
		}
		my @arr_ret = &get_wwwpage($url, $arr_tmp[0]);

		my $ret_msg = "Unknown error.";
		if ($arr_ret[0] > 0) {
			$ret_msg = sprintf("%s %s\n", $arr_ret[1]->code, $arr_ret[1]->message);

			my $attach_filename = $arr_ret[1]->filename;
			my @arr_ctype = split(/;/, $arr_ret[1]->header('Content-Type'));
			if (!$arr_ctype[1] && !$arr_ret[1]->header('Content-Encoding')) {
				$arr_ctype[1] = "UTF-8";
			} elsif (!$arr_ctype[1] && $arr_ret[1]->header('Content-Encoding')) {
				# Note: I haven't seen value of this one, so expect unexpected.
				$arr_ctype[1] = $arr_ret[1]->header('Content-Encoding');
			} else {
				# ' charset=UTF-8' is expected
				$arr_ctype[1] = substr($arr_ctype[1], index($arr_ctype[1], "=")+1);
			}
			if (!$attach_filename) {
				my $suffix = "txt";
				if ($arr_ctype[0] eq 'text/html') {
					$suffix = "html";
				} # if ($res->header('Content-Type')
				$attach_filename = sprintf("file%i.%s", $file_counter, $suffix);
				$file_counter++;
			} # if (!$attach_filename)
			###
			if ($mail_encrypted == 2) {
				my $encrypted = $gpg->sign_encrypt(
					$gpg_my_keyid,
					$gpg_passphrase,
					$arr_ret[1]->content,
					@$gpg_rcpt_keyid
				);
				$attachments.= sprintf("--%s\n", $boundary);
				$attachments.= sprintf("Content-Type: application/octet-stream;\n");
				$attachments.= sprintf(" name=\"%s.pgp\"\n", $attach_filename);
				$attachments.= sprintf("Content-Transfer-Encoding: base64\n");
				$attachments.= sprintf("Content-Disposition: attachment;\n");
				$attachments.= sprintf(" filename=\"%s\.pgp\"\n\n", $attach_filename);
				my @enc_text = split(/\n/, $encrypted);
				foreach (@enc_text) {
					if ($_ =~ / PGP MESSAGE/) {
						next;
					}
					$attachments.= sprintf("%s\n", $_);
				}
			} else {
				$attachments.= sprintf("--%s\n", $boundary);
				$attachments.= sprintf("Content-Type: %s; charset=%s;\n",
					$arr_ctype[0], $arr_ctype[1]);
				$attachments.= sprintf(" name=\"%s\"\n", $attach_filename);
				$attachments.= "Content-Transfer-Encoding: base64\n";
				$attachments.= "Content-Disposition: attachment;\n";
				$attachments.= sprintf(" filename=\"%s\"\n\n", $attach_filename);
				$attachments.= encode_base64($arr_ret[1]->content);
			}
		} else {
			if ($arr_ret[0] == -1) {
				$ret_msg = "Empty URL given.";
			} elsif ($arr_ret[0] == -2) {
				$ret_msg = sprintf("URL must be 'http://' or 'https://', '%s' given.",
					$url);
			} elsif ($arr_ret[0] == -3) {
				$ret_msg = "No method given.";
			} elsif ($arr_ret[0] == -4) {
				$ret_msg = sprintf("Method '%s' is invalid.", $arr_tmp[0]);
			}
		}

		$mail_message.= sprintf("> %s\n%s\n", $mail_body[$i], $ret_msg);
	} else {
		$mail_message.= sprintf("> %s\nNot understood.\n", $mail_body[$i]);
	}
} # for (my $i = 0; ... )

# 7] If body was encrypted, encrypt as well
if ($mail_encrypted == 1) {
	# mail was just GPG signed, do the same.
	my $mail_message_enc = $gpg->clearsign(
		$gpg_my_keyid,
		$gpg_passphrase,
		$mail_message,
	);
	if (!$mail_message_enc) {
		printf STDERR "Failed to encrypt mail message: %s\n", $!;
		printf STDERR "GPG error was: %s\n", $gpg->error();
		exit(1);
	}
	$mail_message = $mail_message_enc;
} elsif ($mail_encrypted == 2) {
	# mail was GPG encrypted, do the same.
	my $mail_message_enc = $gpg->sign_encrypt(
		$gpg_my_keyid,
		$gpg_passphrase,
		$mail_message,
		@$gpg_rcpt_keyid
	);
	if (!$mail_message_enc) {
		printf STDERR "Failed to encrypt mail message: %s\n", $!;
		printf STDERR "GPG error was: %s\n", $gpg->error();
		exit(1);
	}
	$mail_message = $mail_message_enc;
}
# 8] create Mail::Sendmail, attach fetched page, 
my $tmp_str = encode_base64("Re: ".join(" ",
	$mime_entity_in->head->get("Subject")));
my $subject_enc = "";
for my $chunk ( split(/\n/, $tmp_str) ) {
	chomp($chunk);
	next unless ($chunk);
	$subject_enc.= "=?UTF-8?B?".$chunk."?= ";
}

my %mail = (
	Boundary => $boundary,
	Encoding => '8bit',
	From => $my_email,
	Subject => $subject_enc,
	To => $email_from,
	Type => "multipart/mixed",
);
if (!%mail) {
	die ("Failed to create Mail::Simple ".$!);
}

if ($my_smtp) {
	$mail{'Smtp'} = $my_smtp;
}

$mail{'content-type'} = "multipart/mixed;";
$mail{'content-type'}.= "boundary=\"$boundary\"";

my $boundary_begin = sprintf("--%s", $boundary);
my $boundary_end = sprintf("%s--", $boundary);
$mail{body} = <<END_OF_BODY;
$boundary_begin
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

$mail_message
$attachments
$boundary_end
END_OF_BODY
# Mail-out
sendmail(%mail) || print "Error: $Mail::Sendmail::error\n";

=head1 NAME

mail-webpage - script to parse e-mail, get page(s) and mail them back

=head1 DESCRIPTION

Script which reads an e-mail from STDIN, parses its body for commands,
downloads web pages and mails them back. It seems to be one of the ways how to
anonymize browsing. The original idea was pitched in one interview with RMS.

Script utilizes GPG for authentification/authorization and privacy. Encryption
of message and attachments is supported.

=head1 REQUIREMENTS

 - Perl and some Perl packages
 - Postfix or another mail server
 - GnuPG tools

=head1 INSTALLATION

Installation and configuration of Postifx is beyond the scope of this help.
It is assumed you know how to properly configure and administer Posfix.

It is also assumed you know how to configure GnuPG. Some information can be
found here - http://www.madboa.com/geek/gpg-quickstart/

Following text is just a proposition. Excercise your liberty to alter or
develop your own configuration.

  - # mkdir /var/lib/mail-page/;
  - # mkdir /var/lib/mail-page/tmp/;
  - # mkdir /var/lib/mail-page/.gpg/;
  - # chown nobody:root /var/lib/mail-page/;
  - # chmod 750 /var/lib/mail-page/;
  - # cd /var/lib/mail-page/;
  - # chmod 700 /var/lib/mail-page/.gpg/;
  - # gpg --homedir /var/lib/mail-page/.gpg/ --gen-key;
  - # chown -R nobody:root /var/lib/mail-page/.gpg/;
  - Import your public key or keys of your users
  - # vim /etc/postfix/aliases ; and add line:

  ALIAS: |/var/lib/mail-page/mail-page.pl

  - # newaliases; or # postmap /etc/postfix/aliases;
  - edit mail-webpage.pl and configure it
  - # postfix reload;

=head1 CONFIGURATION

  use lib <PATH>; - path to GPGmod.pm (mandatory)
  $debug = integer; - turns on debugging output
  $home_dir = <PATH>; - base directory
  $tmp_dir = <PATH>; - temporary directory used by MIME to dump messages

=head2 SMTP settings

  $my_user = "user"; - e-mail alias for receiving mail-page mails(mandatory)
  $my_domain = "example.com"; - our domain we're sitting at(mandatory)
  $my_smtp = ""; - address of SMTP server(non-mandatory)

=head2 Plain-text email validation

  $disable_plaintext = 1; - disables plain-text/non-signed e-mails
  $file_users = ""; - ACL file with e-mail addresses(non-mandatory)
  $mail_validity = 0; - validity score we're starting with
  $mail_validity_min = 5; - e-mail is valid when this score is reached
  $my_subject = "someSubject"; - subject of e-mail that's expected

=head2 LWP settings

  $max_wwwpage_size = 2097152; - maximum size of fetched page
  @protocols_forbidden = qw(file mail); - forbidden protocols
  @proxy_schemes = qw//; - proxy protocols
  $proxy_url = ""; - proxy proto:addr:port

=head2 GPG settings

  $gpg_homedir = <PATH>; - GnuPG homedir(mandatory?)
  $gpg_passphrase = "12345678"; - secret key passphrase(mandatory)
  $gpg_my_keyid = "CEB62607"; - our secret key ID(mandatory)

=head1 FAQ

 Q: When is e-mail considered valid?
 A: It depends whether e-mail is plain-text, signed or encrypted.
 - Plain-text checks for header fields and is really not recommended to use
 - Signed e-mail has its signature verified and signature must be known
 - Encrypted e-mails are probably obvious; decryption must be successful

 Q: Why have you used GPG.pm?
 A: Because it was the only one that worked. I've started with GPG.pm, then
found out it was missing some features and it actually was abandoned by its
original author. So I've tried couple other packages, which didn't work one
way or another, and ended up back with GPG.pm. I've hacked in features I wanted
and here we are.
If you come up with better solution, if you actually do one, let me know ;)

 Q: Why don't you use GPG MIME?
 A: Well, actually I had. Actually, I think it was working properly. However,
it didn't with Enigmail in Mozilla Thunderbird. Ok, I don't know for sure.

 Q: What's the origin of this script? Where did it come from?
 A: RMS pitched this idea in one of his interviews. He said he's never browsing
intranet from his own computer and that he has script like this. He didn't share
details and I didn't look for any. I used my imagination and implemented GnuPG
encryption, because e-mails are monitored nowadays.
It is even possible something like this exists already and is freely available.
Again, I didn't look for it, I wanted to try and do it myself.

 Q: Don't you think this is somewhat pointless since we have projects like Tor?
 A: No. More tools, more ways we have, better. This might not be the best, might
not be the brightest and perhaps outdated, but I still think it's worth having.

=head1 Known Issues

When updating GnuPG keys files do get chowned to root, resp. to UID used to
update keys. There are two ways to solve it. First, simply watch out. Second,
use user, eg. nobody, that's supposed to own these files :)

Error handling is somewhat ... terrible. I believe it could be solved by writing
up function that would mail error to postmaster, or whatever. On the other hand,
I think MTA will handle this once message "time-outs" in queue.

Be careful! Even though you don't view web page directly, I've seen pages that
I'll load all the missing content from web, eg. pictures, CSS, scripts. Yes, it
means they'll rat you out.

Debugging might be a problematic. What proven to be a good method is to save
e-mail into file, and then just % cat file.txt | perl mail-webpage.pl ; with
debug on.

I can't and won't claim all issues are handled and accounted for.

=cut

# EOF
