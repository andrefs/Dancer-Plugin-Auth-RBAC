# ABSTRACT: Dancer::Plugin::Auth::RBAC authentication via DBIC!

package Dancer::Plugin::Auth::RBAC::Credentials::DBIC;
BEGIN {
  $Dancer::Plugin::Auth::RBAC::Credentials::DBIC::VERSION = '1.110430';
}
BEGIN {
  $Dancer::Plugin::Auth::RBAC::Credentials::DBIC::VERSION = '0.1';
}

use strict;
use warnings;
use Dancer::Plugin;
use base qw/Dancer::Plugin::Auth::RBAC::Credentials/;
use Dancer::Plugin::DBIC;
#use Dancer::Plugin::DebugDump;

my $settings = undef;

sub authorize {
    
    my ($self, $options, @arguments) = @_;
    my ($login, $password) = @arguments;
    
    my $settings = $Dancer::Plugin::Auth::RBAC::settings;
    
    if ($login) {
    
    # authorize a new account using supplied credentials
        
        unless ($password) {
            $self->errors('login and password are required');
            return 0;
        }
    
		my $schema = schema _get_schema_name($options->{handle});
		my $accounts = $schema->resultset('User')->find({
			login => $login,
			password => $password
		}, {
			result_class => 'DBIx::Class::ResultClass::HashRefInflator',
			columns => [qw/id name login roles/]
		});

        if (defined $accounts) {
            
            my $session_data = {
                id    => $accounts->{id},
                name  => $accounts->{name},
                login => $accounts->{login},
                roles => [
                    map { $_ =~ s/^\s+|\s+$//; $_  }
                    split /\,/, $accounts->{roles}
                ],
                error => []
            };
            return $self->credentials($session_data);
            
        }
        else {
            $self->errors('login and/or password is invalid');
            return 0;
        }
    
    }
    else {
        
    # check if current user session is authorized
        
        my $user = $self->credentials;
        if (($user->{id} || $user->{login}) && !@{$user->{error}}) {
            
            return $user;
            
        }
        else {
            $self->errors('you are not authorized', 'your session may have ended');
            return 0;
        }
        
    }
    return 0;
}


sub _get_schema_name{
	my $handle = shift; #$options->{handle}
	my $settings = plugin_setting; # Load DBIC settings

	# If there was an entry options->handle in Authorize settings, return it
	if(defined($handle)){
		return $handle; 
	}

	# If there was not, there must be only one entry under DBIC, so return it
	else {
		my @keys = keys %$settings; # There should be only one!
		$handle = shift @keys;
		return $handle;
	}
}
	
1;


=pod

=head1 NAME

Dancer::Plugin::Auth::RBAC::Credentials::DBIC - Dancer::Plugin::Auth::RBAC authentication via DBIC!

=head1 VERSION

version 1.110430

=head1 SYNOPSIS

    # in your app code
    my $auth = auth($login, $password);
    if ($auth) {
        # login successful
    }
    
    # use your own encryption (if the user account password is encrypted)
    my $auth = auth($login, encrypt($password));
    if ($auth) {
        # login successful
    }

=head1 DESCRIPTION

Dancer::Plugin::Auth::RBAC::Credentials::DBIC uses Dancer::Plugin::DBIC to 
use your DBIx::Class connection as the application's user management system.

=head1 NAME

Dancer::Plugin::Auth::RBAC::Credentials::DBIC - Dancer::Plugin::Authorize authentication via DBIx::Class!

=head1 VERSION

version 0.1

=head1 METHODS

=head2 authorize

The authorize method (found in every authentication class) validates a user against
the defined datastore using the supplied arguments and configuration file options.

=head1 CONFIGURATION

    plugins:
      DBIC:
		foo:
			dsn="dbi:SQLite:dbname=foo.db"
      Auth::RBAC:
        credentials:
          class: DBIC

Sometime you might define multiple connections for the DBIC plugin, make
sure you tell the Auth::RBAC plugin about it... e.g.

    plugins:
      DBIC:
        foo:
          dsn: dbi:SQLite:dbname=./foo.db
        bar:
          schema_class: Foo::Bar
          dsn:  dbi:mysql:db_foo
          user: root
          pass: secret
          options:
            RaiseError: 1
            PrintError: 1
      Auth::RBAC:
        credentials:
          class: SQLite
          options:
            handle: foo

Please see L<Dancer::Plugin::Database> for a list of all available connection
options and arguments.

More information about the database connection in L<Dancer::Plugin::DBIC>

=head1 DATABASE SETUP

    # users table (feel free to add more columns as you see fit)
    
    CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) DEFAULT NULL,
    login VARCHAR(255) NOT NULL,
    password TEXT NOT NULL,
    roles TEXT
    );
    
    # create an initial adminstrative user (should probably encrypt the password)
    # Note! this module is not responsible for creating user accounts, it simply
    # provides a consistant authentication framework
    
    INSERT INTO users (name, login, password, roles)
    VALUES ('Administrator', 'admin', '*****', 'guest, user, admin');

=head1 AUTHOR

Al Newkirk <awncorp@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2010 by awncorp.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=head1 AUTHOR

Al Newkirk <awncorp@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2010 by awncorp.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut


__END__

