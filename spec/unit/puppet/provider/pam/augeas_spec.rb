#!/usr/bin/env rspec
# frozen_string_literal: true

require 'spec_helper'

provider_class = Puppet::Type.type(:pam).provider(:augeas)

describe provider_class do
  before do
    allow(FileTest).to receive(:exist?).and_return(false)
  end

  context 'with empty file' do
    let(:tmptarget) { aug_fixture('empty') }
    let(:target) { tmptarget.path }

    it 'creates simple new entry' do
      apply!(Puppet::Type.type(:pam).new(
               title: 'Add pam_test.so to auth for system-auth',
               service: 'system-auth',
               type: 'auth',
               control: 'sufficient',
               module: 'pam_test.so',
               arguments: 'test_me_out',
               position: 'before module pam_deny.so',
               target: target,
               provider: 'augeas',
               ensure: 'present'
             ))

      aug_open(target, 'Pam.lns') do |aug|
        expect(aug.get('./1/module')).to eq('pam_test.so')
        expect(aug.get('./1/argument[1]')).to eq('test_me_out')
      end
    end

    it 'creates simple new entry without arguments' do
      apply!(Puppet::Type.type(:pam).new(
               title: 'Add pam_test.so to auth for system-auth',
               service: 'system-auth',
               type: 'auth',
               control: 'sufficient',
               module: 'pam_test.so',
               target: target,
               provider: 'augeas',
               ensure: 'present'
             ))

      aug_open(target, 'Pam.lns') do |aug|
        expect(aug.get('./1/module')).to eq('pam_test.so')
        expect(aug.match('./1/argument').size).to eq(0)
      end
    end

    it 'creates two new entries' do
      apply!(Puppet::Type.type(:pam).new(
               title: 'Add pam_test.so to auth for system-auth',
               service: 'system-auth',
               type: 'auth',
               control: 'sufficient',
               module: 'pam_test.so',
               arguments: 'test_me_out',
               target: target,
               provider: 'augeas',
               ensure: 'present'
             ))
      apply!(Puppet::Type.type(:pam).new(
               title: 'Add pam_test.so to auth for system-auth',
               service: 'system-auth',
               type: 'auth',
               control: 'required',
               module: 'pam_unix.so',
               arguments: 'broken_shadow',
               target: target,
               provider: 'augeas',
               ensure: 'present'
             ))

      aug_open(target, 'Pam.lns') do |aug|
        expect(aug.match("*[type='auth']").size).to eq(2)
      end
    end
  end

  context 'with full file' do
    let(:tmptarget) { aug_fixture('full') }
    let(:target) { tmptarget.path }

    it 'lists instances' do
      allow(provider_class).to receive(:target).and_return(target)
      inst = provider_class.instances.map do |p|
        {
          ensure: p.get(:ensure),
          service: p.get(:service),
          type: p.get(:type),
          control: p.get(:control),
          module: p.get(:module),
          arguments: p.get(:arguments),
        }
      end

      expect(inst.size).to eq(21)
      expect(inst[0]).to eq({ ensure: :present,
                              service: :absent,
                              type: 'auth',
                              control: 'required',
                              module: 'pam_env.so',
                              arguments: [], })
      expect(inst[1]).to eq({ ensure: :present,
                              service: :absent,
                              type: 'auth',
                              control: 'sufficient',
                              module: 'pam_unix.so',
                              arguments: %w[nullok try_first_pass], })
      expect(inst[5]).to eq({ ensure: :present,
                              service: :absent,
                              type: 'account',
                              control: 'required',
                              module: 'pam_unix.so',
                              arguments: ['broken_shadow'], })
      expect(inst[8]).to eq({ ensure: :present,
                              service: :absent,
                              type: 'account',
                              control: '[default=bad success=ok user_unknown=ignore]',
                              module: 'pam_sss.so',
                              arguments: [], })
      expect(inst[10]).to eq({ ensure: :present,
                               service: :absent,
                               type: 'password',
                               control: 'requisite',
                               module: 'pam_pwquality.so',
                               arguments: ['try_first_pass', 'retry=3', 'type='], })
    end

    describe 'when reodering settings' do
      it 'changes the order of an entry' do
        apply!(Puppet::Type.type(:pam).new(
                 title: 'Change the order of pam_unix.so',
                 service: 'system-auth',
                 type: 'auth',
                 control: 'sufficient',
                 module: 'pam_unix.so',
                 arguments: %w[nullok try_first_pass],
                 target: target,
                 provider: 'augeas',
                 position: 'before module pam_env.so',
                 ensure: 'positioned'
               ))

        aug_open(target, 'Pam.lns') do |aug|
          expect(aug.get('./1/module')).to eq('pam_unix.so')
        end
      end
    end

    describe 'when creating settings' do
      it 'creates simple new entry' do
        apply!(Puppet::Type.type(:pam).new(
                 title: 'Add pam_test.so to auth for system-auth',
                 service: 'system-auth',
                 type: 'auth',
                 control: 'sufficient',
                 module: 'pam_test.so',
                 arguments: 'test_me_out',
                 position: 'before module pam_deny.so',
                 target: target,
                 provider: 'augeas',
                 ensure: 'present'
               ))

        aug_open(target, 'Pam.lns') do |aug|
          expect(aug.get('./5/module')).to eq('pam_test.so')
          expect(aug.get('./5/argument[1]')).to eq('test_me_out')
        end
      end
    end

    describe 'when modifying settings' do
      it 'Changing the number of retries' do
        apply!(Puppet::Type.type(:pam).new(
                 title: 'Set retry count for pwquality',
                 service: 'system-auth',
                 type: 'password',
                 control: 'requisite',
                 module: 'pam_pwquality.so',
                 arguments: ['try_first_pass', 'retry=4', 'type='],
                 target: target,
                 provider: 'augeas',
                 ensure: 'present'
               ))

        aug_open(target, 'Pam.lns') do |aug|
          expect(aug.match('./*[type="password" and module="pam_pwquality.so" and argument="retry=4"]').size).to eq(1)
        end
      end

      it 'removes the type= argument' do
        apply!(Puppet::Type.type(:pam).new(
                 title: 'Remove type= from pwquality check',
                 service: 'system-auth',
                 type: 'password',
                 control: 'requisite',
                 module: 'pam_pwquality.so',
                 arguments: ['try_first_pass', 'retry=4'],
                 target: target,
                 provider: 'augeas',
                 ensure: 'present'
               ))

        aug_open(target, 'Pam.lns') do |aug|
          expect(aug.match('./*[type="password" and module="pam_pwquality.so" and argument="type="]').size).to eq(0)
        end
      end

      it 'changes the value of control' do
        apply!(Puppet::Type.type(:pam).new(
                 title: 'Remove type= from pwquality check',
                 service: 'system-auth',
                 type: 'password',
                 control: 'required',
                 arguments: ['try_first_pass', 'retry=4'],
                 module: 'pam_pwquality.so',
                 target: target,
                 provider: 'augeas',
                 ensure: 'present'
               ))

        aug_open(target, 'Pam.lns') do |aug|
          expect(aug.get('./*[type="password" and module="pam_pwquality.so"]/control')).to eq('required')
        end
      end

      it 'adds a new entry when control_is_param is true' do
        apply!(Puppet::Type.type(:pam).new(
                 title: 'Remove type= from pwquality check',
                 service: 'system-auth',
                 type: 'password',
                 control: 'sufficient',
                 control_is_param: true,
                 arguments: ['try_first_pass', 'retry=4'],
                 module: 'pam_pwquality.so',
                 target: target,
                 provider: 'augeas',
                 ensure: 'present'
               ))

        aug_open(target, 'Pam.lns') do |aug|
          expect(aug.match('./*[type="password" and module="pam_pwquality.so"]/control').size).to eq(2)
          expect(aug.get('./*[type="password" and module="pam_pwquality.so"][1]/control')).to eq('requisite')
          expect(aug.get('./*[type="password" and module="pam_pwquality.so"][2]/control')).to eq('sufficient')
        end
      end

      it 'updates entry when control_is_param is true' do
        apply!(Puppet::Type.type(:pam).new(
                 title: 'Remove type= from pwquality check',
                 service: 'system-auth',
                 type: 'password',
                 control: 'requisite',
                 control_is_param: true,
                 arguments: ['try_first_pass', 'retry=4'],
                 module: 'pam_pwquality.so',
                 target: target,
                 provider: 'augeas',
                 ensure: 'present'
               ))

        aug_open(target, 'Pam.lns') do |aug|
          expect(aug.match('./*[type="password" and module="pam_pwquality.so"]/control').size).to eq(1)
          expect(aug.get('./*[type="password" and module="pam_pwquality.so"]/control')).to eq('requisite')
        end
      end
    end

    describe 'when removing settings' do
      it 'removes the entry' do
        apply!(Puppet::Type.type(:pam).new(
                 title: 'Remove pwquality entry',
                 service: 'system-auth',
                 type: 'password',
                 control: 'requisite',
                 module: 'pam_pwquality.so',
                 arguments: ['try_first_pass', 'retry=4'],
                 target: target,
                 provider: 'augeas',
                 ensure: 'absent'
               ))

        aug_open(target, 'Pam.lns') do |aug|
          expect(aug.match('./*[type="password" and module="pam_pwquality.so"]').size).to eq(0)
        end
      end
    end
  end

  context 'with broken file' do
    let(:tmptarget) { aug_fixture('broken') }
    let(:target) { tmptarget.path }

    it 'fails to load' do
      txn = apply(Puppet::Type.type(:pam).new(
                    title: 'Ensure pwquality is configured',
                    service: 'system-auth',
                    type: 'password',
                    control: 'requisite',
                    module: 'pam_pwquality.so',
                    arguments: ['try_first_pass', 'retry=3', 'type='],
                    target: target,
                    provider: 'augeas',
                    ensure: 'present'
                  ))

      expect(txn.any_failed?).not_to eq(nil)
      expect(@logs.first.level).to eq(:err) # rubocop:todo RSpec/InstanceVariable
      expect(@logs.first.message.include?(target)).to eq(true) # rubocop:todo RSpec/InstanceVariable
    end
  end

  context 'with Ubuntu 24.04 configuration' do
    let(:tmptarget) { aug_fixture('ubuntu2404') }
    let(:target) { tmptarget.path }

    it 'lists instances correctly for Ubuntu 24.04 PAM format' do
      allow(provider_class).to receive(:target).and_return(target)
      inst = provider_class.instances.map do |p|
        {
          ensure: p.get(:ensure),
          service: p.get(:service),
          type: p.get(:type),
          control: p.get(:control),
          module: p.get(:module),
          arguments: p.get(:arguments),
        }
      end

      expect(inst.size).to eq(16)
      # Test first auth entry
      expect(inst[0]).to eq({ ensure: :present,
                              service: :absent,
                              type: 'auth',
                              control: '[success=1 default=ignore]',
                              module: 'pam_unix.so',
                              arguments: ['nullok'], })
      # Test password entry with yescrypt at index 7
      expect(inst[7]).to eq({ ensure: :present,
                              service: :absent,
                              type: 'password',
                              control: '[success=1 default=ignore]',
                              module: 'pam_unix.so',
                              arguments: %w[obscure use_authtok try_first_pass yescrypt], })
      # Test systemd session entry
      expect(inst[15]).to eq({ ensure: :present,
                               service: :absent,
                               type: 'session',
                               control: 'optional',
                               module: 'pam_systemd.so',
                               arguments: [], })
    end

    it 'can modify Ubuntu 24.04 style PAM entries' do
      apply!(Puppet::Type.type(:pam).new(
               title: 'Configure pam_faillock for Ubuntu 24.04',
               service: 'common-auth',
               type: 'auth',
               control: 'required',
               module: 'pam_faillock.so',
               arguments: ['preauth', 'silent', 'audit', 'deny=5', 'unlock_time=900'],
               position: 'before module pam_unix.so',
               target: target,
               provider: 'augeas',
               ensure: 'present'
             ))

      aug_open(target, 'Pam.lns') do |aug|
        expect(aug.get('./1/module')).to eq('pam_faillock.so')
        expect(aug.get('./1/control')).to eq('required')
        expect(aug.get('./1/argument[1]')).to eq('preauth')
        expect(aug.get('./1/argument[4]')).to eq('deny=5')
      end
    end

    it 'can add new PAM module to Ubuntu 24.04 configuration' do
      # Add a completely new module that doesn't exist
      apply!(Puppet::Type.type(:pam).new(
               title: 'Add pam_faillock for Ubuntu 24.04',
               service: 'common-auth',
               type: 'auth',
               control: 'required',
               module: 'pam_faillock.so',
               arguments: ['preauth', 'silent', 'audit', 'deny=5'],
               position: 'before module pam_deny.so',
               target: target,
               provider: 'augeas',
               ensure: 'present'
             ))

      aug_open(target, 'Pam.lns') do |aug|
        # Check that pam_faillock.so was added
        faillock_entries = aug.match('./*[type="auth" and module="pam_faillock.so"]')
        expect(faillock_entries.size).to eq(1)
        # Verify the arguments
        expect(aug.get("#{faillock_entries.first}/argument[1]")).to eq('preauth')
        expect(aug.get("#{faillock_entries.first}/argument[4]")).to eq('deny=5')
      end
    end

    it 'handles yescrypt password hashing correctly' do
      apply!(Puppet::Type.type(:pam).new(
               title: 'Update password hashing to yescrypt',
               service: 'common-password',
               type: 'password',
               control: '[success=1 default=ignore]',
               module: 'pam_unix.so',
               arguments: %w[obscure use_authtok try_first_pass yescrypt rounds=5],
               target: target,
               provider: 'augeas',
               ensure: 'present'
             ))

      aug_open(target, 'Pam.lns') do |aug|
        password_entry = aug.match('./*[type="password" and module="pam_unix.so"]').first
        expect(aug.get("#{password_entry}/argument[5]")).to eq('rounds=5')
        expect(aug.match("#{password_entry}/argument[.='yescrypt']").size).to eq(1)
      end
    end
  end
end
