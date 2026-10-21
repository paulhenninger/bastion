import { ActivitySection, DataSection, SessionsSection } from './account/ActivitySections';
import { EmailSection, PasswordSection, ProfileSection } from './account/CredentialsSections';
import { PasskeysSection } from './account/PasskeysSection';
import { TwoFactorSection } from './account/TwoFactorSection';

/** Everything a user can do to their own account. Sensitive actions prompt "confirm it's you". */
export default function AccountPage() {
  return (
    <>
      <h1>Account &amp; security</h1>
      <ProfileSection />
      <PasskeysSection />
      <TwoFactorSection />
      <PasswordSection />
      <EmailSection />
      <SessionsSection />
      <ActivitySection />
      <DataSection />
    </>
  );
}
