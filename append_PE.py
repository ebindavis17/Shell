def does_principal_allow_public_access(self, principal):
        if principal == '*':
            return True
        elif 'AWS' in principal:

            accounts = principal['AWS']
            accounts = accounts if type(accounts) is list else [accounts]
            for account in accounts:
                if account == '*':
                    return True
                match = re.match(ARN_REGEX, account)
                if  match:
                    print('Warning: allowing access from {}'.format(match.group('account_id')))

                else:
                    print('Warning: unknown principal {}'. format(account))

        return False

