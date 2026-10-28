# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'pam' do
  before(:all) do
    shell("printf 'auth required pam_env.so\\nauth required pam_deny.so\\n' > /etc/pam.d/puppet-test")
  end

  context 'with ensure => present' do
    it_behaves_like 'an idempotent resource' do
      let(:manifest) do
        <<~PUPPET
          pam { 'Set pam_unix in puppet-test auth':
            ensure    => present,
            service   => 'puppet-test',
            type      => 'auth',
            control   => 'sufficient',
            module    => 'pam_unix.so',
            arguments => ['nullok', 'try_first_pass'],
            position  => 'before module pam_deny.so',
          }
        PUPPET
      end
    end

    describe file('/etc/pam.d/puppet-test') do
      its(:content) { is_expected.to match(%r{^auth\s+required\s+pam_env\.so\nauth\s+sufficient\s+pam_unix\.so\s+nullok\s+try_first_pass\nauth\s+required\s+pam_deny\.so$}) }
    end
  end

  context 'with ensure => absent' do
    it_behaves_like 'an idempotent resource' do
      let(:manifest) do
        <<~PUPPET
          pam { 'Remove pam_unix from puppet-test auth':
            ensure  => absent,
            service => 'puppet-test',
            type    => 'auth',
            module  => 'pam_unix.so',
          }
        PUPPET
      end
    end

    describe file('/etc/pam.d/puppet-test') do
      its(:content) { is_expected.not_to match(%r{pam_unix}) }
      its(:content) { is_expected.to match(%r{^auth\s+required\s+pam_deny\.so$}) }
    end
  end
end
