package MT::Plugin::MFA::Email;

use strict;
use warnings;
use utf8;

sub plugin {
    my $name = __PACKAGE__;
    $name =~ s{\AMT::Plugin::}{};
    $name =~ s{::}{-}g;
    MT->component($name);
}

sub _cache_driver {
    require MT::Cache::Negotiate;

    MT::Cache::Negotiate->new(
        ttl       => 5 * 60,
        expirable => 1,
    );
}

sub _cache_key {
    require MT::Util;

    my ($user, $token) = @_;
    MT::Util::perl_sha1_digest_hex(join('::', $user->id, $token));
}

sub render_form {
    my ($cb, $app, $param) = @_;

    if (my $user = $app->user) {
        my $token = sprintf('%06d', rand 1000000);
        _cache_driver()->set(_cache_key($user, $token), $token);

        my %head = (
            id      => 'fma_email',
            To      => $user->email,
            Subject => plugin()->translate('Security token for signing in to the Movable Type'),
        );

        my $body = MT->build_page_in_mem(plugin()->load_tmpl('email.tmpl'), {
            token => $token,
        });

        require MT::Mail;
        MT::Mail->send( \%head, $body )
            or $app->log({
                message => $app->translate(
                    'Error sending mail: [_1]',
                    MT::Mail->errstr
                ),
                level    => MT::Log::ERROR(),
                class    => 'system',
                category => 'email'
            });
    }

    push @{$param->{templates}}, plugin()->load_tmpl('form.tmpl');
}

sub verify_token {
    my ($cb) = @_;
    my $app = MT->app;

    (my $token = $app->param('mfa_email_token') || '') =~ s/\s+//g;

    return 0 unless $token =~ m/\A\d{6}\z/;

    my $cache_driver = _cache_driver();
    my $cache_key = _cache_key($app->user, $token);
    return 0 unless ($cache_driver->get($cache_key) || '') eq $token;

    $cache_driver->set($cache_key, ''); # clear

    return 1;
}

1;
