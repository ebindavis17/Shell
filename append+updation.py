def does_principal_allow_public_access(self, principal):
        if principal == '*':
            return True
        elif 'AWS' in principal:
            accounts = principal['AWS']
            accounts = accounts if type(accounts) is list else [accounts]
            for account in accounts:
                match = re.match(ARN_REGEX, account)
                if not match:
                    return True
                else:
                    print('Warning: allowing access from {}'.format(match.group('account_id')))

        return False