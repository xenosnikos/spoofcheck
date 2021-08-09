import os
from flask_restful import Resource, reqparse, request, inputs
from enum import Enum
from helpers import auth_check, spoofcheck, common_strings, logging_setup, queue_to_db, utils

portscan_args = reqparse.RequestParser()

portscan_args.add_argument(common_strings.strings['key_value'], help=common_strings.strings['domain_required'], required=True)
portscan_args.add_argument(common_strings.strings['input_force'], type=inputs.boolean, default=False)
logger = logging_setup.initialize(common_strings.strings['spoofcheck'], 'logs/spoofcheck_api.log')

class Risk(Enum):
    FAIL = "FAIL"
    PASS = "PASS"

class SpoofCheck(Resource):

    @staticmethod
    def post():
        args = portscan_args.parse_args()

        value = args['value']

        logger.debug(f"spoofcheck request received for {value}")

        auth = request.headers.get(common_strings.strings['auth'])

        authentication = auth_check.auth_check(auth)

        if authentication['status'] == 401:
            logger.debug(f"Unauthenticated WhoIs request received for {value}")
            return authentication, 401

        if not utils.validate_domain(value):  # if regex doesn't match throw a 400
            logger.debug(f"Domain that doesn't match regex request received - {value}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings['invalid_domain']
                   }, 400
        
        # if domain doesn't resolve into an IP, throw a 400 as domain doesn't exist in the internet
        try:
            ip = utils.resolve_domain_ip(value)
        except Exception as e:
            logger.debug(f"Domain that doesn't resolve to an IP was requested - {value, e}")
            return {
                       common_strings.strings['message']: f"{value}" + common_strings.strings['unresolved_domain_ip']
                   }, 400

        if args[common_strings.strings['input_force']]:
            force = True
        else:
            force = False  

        # based on force - either gives data back from database or gets a True back to continue with a fresh scan
        check = utils.check_force(value, force, collection=common_strings.strings['spoofcheck'],
                                  timeframe=int(os.environ.get('DATABASE_LOOK_BACK_TIME')))    
        
        # if a scan is already requested/in-process, we send a 202 indicating that we are working on it
        if check == common_strings.strings['status_running'] or check == common_strings.strings['status_queued']:
            return {'status': check}, 202
        
        # if database has an entry with results and force is false, send it
        elif type(check) == dict and check['status'] == common_strings.strings['status_finished']:
            logger.debug(f"spoofcheck scan response sent for {value} from database lookup")
            return check['output'], 200

        else:
            # mark in db that the scan is queued
            utils.mark_db_request(value, status=common_strings.strings['status_queued'],
                                  collection=common_strings.strings['spoofcheck'])
            output = {common_strings.strings['key_value']: value, common_strings.strings['key_ip']: ip}
        
        try:
            spoofcheck_data = spoofcheck.main_check(value)
            output.update(spoofcheck_data)
            output['risk'] = Risk.PASS.name if output['message'].count("not possible")>0 else Risk.FAIL.name
        except Exception as e:
            logger.critical(common_strings.strings['error'], exc_info=e)
            return 'spoofcheck scan is currently unavailable', 503
        queue_to_db.spoofcheck_response_db_addition(value, output)
        return output, 200