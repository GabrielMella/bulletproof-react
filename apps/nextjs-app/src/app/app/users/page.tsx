import { ContentLayout } from '@/components/layouts/content-layout';
import { getUser } from '@/lib/auth';
import { canViewUsers } from '@/lib/authorization';

import { Users } from './_components/users';

export const metadata = {
  title: 'Users',
  description: 'Users',
};

const UsersPage = async () => {
  const user = await getUser();

  if (!canViewUsers(user)) {
    return (
      <ContentLayout title="Users">
        <div>Only admin can view this.</div>
      </ContentLayout>
    );
  }

  return (
    <ContentLayout title="Users">
      <Users />
    </ContentLayout>
  );
};

export default UsersPage;
