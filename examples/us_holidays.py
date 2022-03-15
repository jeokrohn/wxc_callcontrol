"""
Create a holiday schedule for all US locations with all national holidays
"""

import logging
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from threading import Lock
from typing import List

from calendarific import CalendarifiyApi, Holiday
from dotenv import load_dotenv
from webex_simple_api import WebexSimpleApi
from webex_simple_api.locations import Location
from webex_simple_api.telephony.schedules import ScheduleType, Event, Schedule

log = logging.getLogger(__name__)

# a lock per location to protect observe_in_location()
location_locks = defaultdict(Lock)


def observe_in_location(*, api: WebexSimpleApi, location: Location, holidays: List[Holiday]):
    """
    create/update a "National Holiday" schedule in one location
    :param api:
    :param location:
    :param holidays:
    :return:
    """
    # there should always only one thread messing with the holiday schedule of a location
    with location_locks[location.location_id]:
        year = holidays[0].date.year
        schedule_name = 'National Holidays'

        # shortcut
        ats = api.telephony.schedules

        # existing "National Holiday" schedule or None
        schedule = next((schedule
                         for schedule in ats.list(location_id=location.location_id,
                                                  schedule_type=ScheduleType.holidays,
                                                  name=schedule_name)
                         if schedule.name == schedule_name),
                        None)
        if schedule:
            # ats.delete_schedule(location_id=location.location_id,
            #                     schedule_type=ScheduleType.holidays,
            #                     schedule_id=schedule.schedule_id)
            # return

            # we need the details: list response doesn't have events
            schedule = ats.details(location_id=location.location_id,
                                   schedule_type=ScheduleType.holidays,
                                   schedule_id=schedule.schedule_id)
        # create list of desired schedule entries
        #   * one per holiday
        #   * only future holidays
        #   * not on a Sunday
        today = date.today()
        events = [Event(name=f'{holiday.name} {holiday.date.year}',
                        start_date=holiday.date,
                        end_date=holiday.date,
                        all_day_enabled=True)
                  for holiday in holidays
                  if holiday.date >= today
                  and holiday.date.weekday() != 6]

        # create new schedule
        if not schedule:
            log.debug(f'observe_in_location({location.name}, {year}): no existing schedule')
            if not events:
                log.info(f'observe_in_location({location.name}, {year}): no existing schedule, no events, done')
                return
            schedule = Schedule(name=schedule_name,
                                schedule_type=ScheduleType.holidays,
                                events=events)
            log.debug(
                f'observe_in_location({location.name}, {year}): creating schedule "{schedule_name}" with {len(events)} '
                f'events')
            schedule_id = ats.create(location_id=location.location_id, schedule=schedule)
            log.info(f'observe_in_location({location.name}, {year}): new schedule id: {schedule_id}, done')
            return

        with ThreadPoolExecutor() as pool:
            # update existing schedule
            # delete events in the past
            to_delete = [event
                         for event in schedule.events
                         if event.start_date < today]
            if to_delete:
                log.debug(f'observe_in_location({location.name}, {year}): deleting {len(to_delete)} outdated events')
                list(pool.map(
                    lambda event: ats.event_delete(location_id=location.location_id,
                                                   schedule_type=ScheduleType.holidays,
                                                   event_id=event.event_id),
                    to_delete))

            # add events which don't exist yet
            existing_dates = set(event.start_date
                                 for event in schedule.events)
            to_add = [event
                      for event in events
                      if event.start_date not in existing_dates]
            if not to_add:
                log.info(f'observe_in_location({location.name}, {year}): no events to add, done.')
                return
            log.debug(f'observe_in_location({location.name, {year} }): creating {len(to_add)} new events.')
            list(pool.map(
                lambda event: ats.event_create(
                    location_id=location.location_id,
                    schedule_type=ScheduleType.holidays,
                    schedule_id=schedule.schedule_id,
                    event=event),
                to_add))
        log.info(f'observe_in_location({location.name}, {year}): done.')
    return


def observe_national_holidays(*, api: WebexSimpleApi, locations: List[Location],
                              year: int = None):
    """
    US national holidays for given locations
    :return:
    """
    # default: this year
    year = year or date.today().year

    # get national holidays for specified year
    holidays = CalendarifiyApi().holidays(country='US', year=year, holiday_type='national')

    # update holiday schedule for each location
    with ThreadPoolExecutor() as pool:
        list(pool.map(lambda location: observe_in_location(api=api, location=location, holidays=holidays),
                      locations))


if __name__ == '__main__':
    # read dotenv from parent directory (.env) has some environment variables like Webex API token and Calendarify
    # API key.
    dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
    load_dotenv(dotenv_path=dotenv_path)

    # enable logging
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s')
    logging.getLogger('urllib3').setLevel(logging.INFO)
    logging.getLogger('webex_simple_api.rest').setLevel(logging.INFO)

    # the actual action
    with WebexSimpleApi(concurrent_requests=5) as wx_api:
        # get all US locations
        us_locations = [location
                        for location in wx_api.locations.list()
                        if location.address.country == 'US']
        # create national holiday schedule for given year(s) and locations
        with ThreadPoolExecutor() as pool:
            list(pool.map(
                lambda year: observe_national_holidays(api=wx_api, year=year, locations=us_locations),
                range(2022, 2031)))
