from webex_simple_api import WebexSimpleApi
from tokens import Tokens
import logging
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from functools import partial


access_token = 'MmQxMTFhYjctN2I5MC00MDA5LTg3ZDktNmFiZWE0NTc3NzlkZWVjNmM2ZjItNjYy_P0A1_36818b6f-ef07-43d1-b76f-ced79ab2e3e7'


def main():
    logging.basicConfig(level=logging.DEBUG)
    tokens = Tokens(access_token=access_token,
                    expires_in=50000,
                    refresh_token='',
                    refresh_token_expires_in=50000,
                    token_type='Bearer')

    with WebexSimpleApi(tokens=tokens) as api:
        people = list(api.people.list(calling_data=True))
        with ThreadPoolExecutor() as pool:
            details = list(pool.map(lambda p:api.people.details(person_id=p.person_id), people))
        no_calling = [p for p in people
                      if p.location_id is None and not p.display_name.startswith('XXX')]
        if no_calling:
            # update display name of users w/o calling
            for user in no_calling:
                user.display_name = f'XXX {user.display_name}'
            pool = ThreadPoolExecutor()
            futures = [pool.submit(partial(api.people.update_person, person=person))
                       for person in no_calling]
            wait(futures, return_when=ALL_COMPLETED)
        people = list(api.people.list(display_name='XXX'))

        print(people)


if __name__ == '__main__':
    main()
