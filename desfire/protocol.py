"""MIFARE DESFire communication protocol for Python.

For DESFire overview:

* http://www.slideshare.net/ashu4india/mifare-des-fire-pres

For list of DESFire commands see:

* https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesFireInstruction.java

* https://www.mifare.net/files/advanced_javadoc/com/nxp/nfclib/desfire/DESFire.html

* https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java

* https://github.com/nfc-tools/libfreefare/blob/master/libfreefare/mifare_desfire.c

* https://github.com/codebutler/farebot/blob/master/src/main/java/com/codebutler/farebot/card/desfire/DesfireProtocol.java

* https://github.com/nceruchalu/easypay/blob/master/mifare/mifare.c

* http://webcache.googleusercontent.com/search?q=cache:6ZnWrYzNzLIJ:apidoc.springcard.com/sprox_desfire/sprox_desfire_auth_c.html+&cd=10&hl=en&ct=clnk&gl=us
"""
from __future__ import print_function

import logging
import time

import pyDes

from .device import Device
from .util import byte_array_to_human_readable_hex, dword_to_byte_array, word_to_byte_array


_logger = logging.getLogger(__name__)


#: File kind bits set on a DESFire file
FILE_TYPES = {
    0x00: "Standard Data Files",
    0x01: "Backup Data Files",
    0x02: "Value Files with Backup",
    0x03: "Linear Record Files with Backup",
    0x04: "Cyclic Record Files with Backup",
}

#: Communication requirements bits set a on DESFire file
FILE_COMMUNICATION = {
    0x00: "Plain communication",
    0x01: "Plain communication secured by DES/3DES MACing",
    0x03: "Fully DES/3DES enciphered communication",
}

#: Error code translation mappings
#: https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java
ERRORS = {
    0x9d: "Permission denied",
    0x1c: "Limited credit",
    0xae: "Authentication error",
    0x7e: "Length error when sending the command",
    0x0c: "No changes",
    0xf0: "File not found",
    0xbd: "File not found",
}


class DESFireCommunicationError(Exception):
    """Outgoing DESFire command received a non-OK reply.

    The exception message is human readable translation of the error code if available. The ``status_code`` carries the original status word error byte.
    """

    def __init__(self, msg, status_code):
        super(DESFireCommunicationError, self).__init__(msg)
        self.status_code = status_code


class DESFire(object):
    """MIFare DEefire EV1 communication protocol for NFC cards."""

    def __init__(self, device, logger=None):
        """
        :param device: :py:class:`desfire.device.Device` implementation
        :param logger: Python :py:class:`logging.Logger` used for logging output. Overrides the default logger. Extensively uses ``INFO`` logging level.
        """

        assert isinstance(device, Device), "Not a compatible device instance: {}".format(device)

        self.device = device

        #: 8 bytes of session key after authenticate()
        self.session_key = None

        if logger:
            self.logger = logger
        else:
            self.logger = _logger

    def decrypt_response(self, response, private_key=b"\00" * 16, session_key=None):
        """Decrypt the autheticated session answer from the card.

        .. warn ::

            Does not check CMAC.
        """

        initial_value = b"\00" * 8
        k = pyDes.triple_des(bytes(private_key), pyDes.CBC, initial_value, pad=None, padmode=pyDes.PAD_NORMAL)

        decrypted = [b for b in (k.decrypt(bytes(response)))]
        import pdb ; pdb.set_trace()

    def communicate(self, apdu_cmd, description, allow_continue_fallthrough=False):
        """Communicate with a NFC tag.

        Send in outgoing request and waith for a card reply.

        TODO: Handle additional framing via 0xaf

        :param apdu_cmd: Outgoing APDU command as array of bytes

        :param description: Command description for logging purposes

        :param allow_continue_fallthrough: If True 0xAF response (incoming more data, need mode data) is instantly returned to the called instead of trying to handle it internally

        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error

        :return: tuple(APDU response as list of bytes, bool if additional frames are inbound)
        """

        result = []
        additional_framing_needed = True

        # TODO: Clean this up so read/write implementations have similar mechanisms and all continue is handled internally
        while additional_framing_needed:

            apdu_cmd_hex = [hex(c) for c in apdu_cmd]
            self.logger.debug("Running APDU command %s, sending: %s", description, apdu_cmd_hex)

            resp = self.device.transceive(apdu_cmd)
            self.logger.debug("Received APDU response: %s", byte_array_to_human_readable_hex(resp))

            if resp[-2] != 0x91:
                raise DESFireCommunicationError("Received invalid response for command: {}".format(description), resp[-2:])

            # Possible status words: https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java
            status = resp[-1]

            # Check for known error interpretation
            error_msg = ERRORS.get(status)
            if error_msg:
                raise DESFireCommunicationError(error_msg, status)

            if status == 0xaf:
                if allow_continue_fallthrough:
                    additional_framing_needed = False
                else:
                    # Need to loop more cycles to fill in receive buffer
                    additional_framing_needed = True
                    apdu_cmd = self.wrap_command(0xaf)  # Continue
            elif status != 0x00:
                raise DESFireCommunicationError("Error {:02x} when communicating".format(status), status)
            else:
                additional_framing_needed = False

            # This will un-memoryview this object as there seems to be some pyjnius
            # bug getting this corrupted down along the line
            unframed = list(resp[0:-2])
            result += unframed

        return result

    @classmethod
    def wrap_command(cls, command, parameters=None):
        """Wrap a command to native DES framing.

        :param command: Command byte

        :param parameters: Command parameters as list of bytes

        https://github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L129
        """
        if parameters:
            return [0x90, command, 0x00, 0x00, len(parameters)] + parameters + [0x00]
        else:
            return [0x90, command, 0x00, 0x00, 0x00]

    def parse_application_list(self, resp):
        """Handle response for command 0x6a list applications.

        DESFire application ids are 24-bit integers.

        :param resp: DESFire response as byte array

        :return: List of parsed application ids
        """
        pointer = 0
        apps = []
        while pointer < len(resp):
            app_id = (resp[pointer] << 16) + (resp[pointer+1] << 8) + resp[pointer+2]
            self.logger.debug("Reading %d %08x", pointer, app_id)
            apps.append(app_id)
            pointer += 3

        return apps

    def get_applications(self):
        """Get all applications listed in Desfire root.

        :return: List of 24-bit integer

        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
        """

        # https://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
        cmd = self.wrap_command(0x6a)
        resp = self.communicate(cmd, "Read applications")
        apps = self.parse_application_list(resp)
        return apps

    def get_card_uid(self):
        """Get card UID number.

        .. note ::

            No idea how this works. Gives you 16 bytes of random data. Don't know how to decrypt.

        http://stackoverflow.com/questions/29819356/apdu-for-get-uid-from-mifare-desfire

        https://www.mifare.net/support/forum/topic/desfire-ev1-uid-unique-and-always-returned/

        :return: 16 bytes of random data?
        """
        cmd = self.wrap_command(0x5f)
        resp = self.communicate(cmd, "Read UID")
        return resp

    def select_application(self, app_id):
        """Choose application on a card on which all the following file commands will apply.

        :param app_id: 24-bit int

        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
        """
        # https://github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L53
        parameters = [
            (app_id >> 16) & 0xff,
            (app_id >> 8) & 0xff,
            (app_id >> 0) & 0xff,
        ]

        apdu_command = self.wrap_command(0x5a, parameters)

        self.communicate(apdu_command, "Selecting application {:06X}".format(app_id))

    def get_file_ids(self):
        # https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireApplet.java#L484
        apdu_command = self.wrap_command(0x6f)
        resp = self.communicate(apdu_command, "Listing files")
        # Byte ids are directly the ids of files
        return resp

    def authenticate(self, key_id, private_key=[0x00] * 16):
        """Hacked together Android only DESFire authentication.

        Desfire supports multiple authentication modes, but this does on triple-DES (TDES, 3DES).

        Here we use legacy authentication (0xa0). After calling this function the :py:class:`DESFire` object is authenticated and will decrypt the future responses using the session key.

        .. warn ::

            This authentication is not a safe and just for demostration purposes.

        More info

        * https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesFireInstruction.java

        * http://stackoverflow.com/questions/14117025/des-send-and-receive-modes-for-desfire-authentication

        :param key_id: One of 0-16 keys stored the card as a byte

        :param private_key: 16 bytes of private key

        :return: session key, 8 bytes
        """

        apdu_command = self.wrap_command(0x0a, [key_id])
        resp = self.communicate(apdu_command, "Authenticating key {:02X}".format(key_id), allow_continue_fallthrough=True)

        # We get 8 bytes challenge
        random_b_encrypted = list(resp)
        assert len(random_b_encrypted) == 8

        initial_value = b"\00" * 8
        k = pyDes.triple_des(bytes(private_key), pyDes.CBC, initial_value, pad=None, padmode=pyDes.PAD_NORMAL)

        decrypted_b = [b for b in (k.decrypt(bytes(random_b_encrypted)))]

        # shift randB one byte left and get randB'
        shifted_b = decrypted_b[1:8] + [decrypted_b[0]]

        # Generate random_a
        # NOT A REAL RANDOM NUMBER AND NOT IV XORRED
        random_a = b"\00" * 8

        decrypted_a = [b for b in k.decrypt(bytes(random_a))]

        xorred = []

        for i in range(0, 8):
            xorred.append(decrypted_a[i] ^ shifted_b[i])

        decrypted_xorred = [b for b in k.decrypt(bytes(xorred))]

        final_bytes = decrypted_a + decrypted_xorred
        assert len(final_bytes) == 16

        apdu_command = self.wrap_command(0xaf, final_bytes)
        resp = self.communicate(apdu_command, "Authenticating continues with key {:02X}".format(key_id))

        assert len(resp) == 8

        self.logger.info("Received session key %s", byte_array_to_human_readable_hex(resp))

        self.session_key = resp

        return resp

        #import pdb ; pdb.set_trace()
        #raise NotImplementedError("Still needs to be done in a proper manner.")

        # from jnius import autoclass
        # from jnius import cast
        #
        # Cipher = autoclass("javax.crypto.Cipher")
        # SecretKeySpec = autoclass("javax.crypto.spec.SecretKeySpec")
        # SecretKeyFactory = autoclass("javax.crypto.SecretKeyFactory")
        # IvParameterSpec = autoclass("javax.crypto.spec.IvParameterSpec")
        # DESKeySpec = autoclass("javax.crypto.spec.DESKeySpec")
        # DESedeKeySpec = autoclass("javax.crypto.spec.DESedeKeySpec")
        # String = autoclass("java.lang.String")
        #
        # apdu_command = self.wrap_command(0x0a, [key_id])
        # resp = self.communicate(apdu_command, "Authenticating application {:06X}".format(app_id))
        #
        # # http://java-card-desfire-emulation.googlecode.com/svn/trunk/java-card-desfire-emulation/Credit%20DESfire%20App/src/credit/DESfireApi.java
        # # http://mrbigzz.blogspot.com/2014/01/android-desfire-authentication.html
        # random_b_encrypted = list(resp)
        # assert len(random_b_encrypted) == 8
        #
        # #bytes = String("xxxxXXXXxxxxXXXX").getBytes()
        # #des_key_spec = DESedeKeySpec(bytes)
        #
        # cipher = Cipher.getInstance("DESede/ECB/NoPadding","BC")
        #
        # secret_key_spec = SecretKeySpec(private_key, "DESede")
        # secret_key = cast("java.security.Key", secret_key_spec)
        #
        # cipher.init(Cipher.DECRYPT_MODE, secret_key)
        # random_b_decrypted = list(cipher.doFinal(random_b_encrypted))
        # self.logger.debug("Decrypted random B %s", byte_array_to_human_readable_hex(random_b_decrypted))
        #
        # # Let's pick up by fire dice
        # # This let's us skip one XOR'ing
        # # http://java-card-desfire-emulation.googlecode.com/svn/trunk/java-card-desfire-emulation/Credit%20DESfire%20App/src/credit/DESfireApi.java
        # random_a = [0x00] * 8
        #
        # cipher.init(Cipher.ENCRYPT_MODE, secret_key)
        #
        # rotated_b = random_b_decrypted[1:] + random_b_decrypted[0:1]
        # cipher_text = list(cipher.update(random_a)) + list(cipher.doFinal(rotated_b))
        #
        # self.logger.debug("Sending in cipher text %s", byte_array_to_human_readable_hex(cipher_text))
        # assert len(cipher_text) == 16
        #
        # apdu_command = self.wrap_command(0xaf, cipher_text)
        # resp = self.communicate(apdu_command, "Sending auth response")

        # http://stackoverflow.com/questions/14319321/how-can-i-do-native-authentication-in-desfire-ev1
        # http://stackoverflow.com/questions/17111451/what-kind-of-block-format-is-the-desfire-authentication-message
        # https://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
        # http://stackoverflow.com/questions/14117025/des-send-and-receive-modes-for-desfire-authentication

    def get_file_settings(self, file_id):
        """Get DESFire file settings.


        :param file_id: File id as a byte

        :return: File description dict.
        """
        apdu_command = self.wrap_command(0xf5, [file_id])
        resp = self.communicate(apdu_command, "Reading file description {:02X}".format(file_id))

        file_desc = {
            "type": FILE_TYPES[resp[0]],
            "communication": FILE_COMMUNICATION[resp[1]],
            "rw_flags": resp[2:4],
        }

        if resp[0] == 0x03:
            # Linear record file
            file_desc.update({
                # Length of ONE records
                "record_length": resp[4] | (resp[5] << 8) | (resp[6] << 16),
                "num_of_records": resp[7],
            })
        elif resp[0] == 0x00:
            # Data file
            file_desc.update({
                "file_length": resp[4] | (resp[5] << 8) | (resp[6] << 16),
            })
        else:
            # TODO: We can still access common attributes
            # raise NotImplementedError("Please fill in logic for file type {:02X}".format(resp[0]))
            pass

        return file_desc

    def get_value(self, file_id):
        """Get stored value.

        :param file_id: Stored value file id
        :return: Integer.
        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
        """
        apdu_command = self.wrap_command(0x6c, [file_id])
        resp = self.communicate(apdu_command, "Reading value {:02X}".format(file_id))
        return (resp[3] << 24) | (resp[2] << 16) | (resp[1] << 8) | resp[0]

    def credit_value(self, file_id, added_value):
        """Increase stored value.

        :param file_id: (byte)

        :param added_value: (int, 32 bit) Value to be added to the current value

        :raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
        """

        value = dword_to_byte_array(added_value)

        apdu_command = self.wrap_command(0x0c, [file_id] + value)
        self.communicate(apdu_command, "Crediting file {:02X} value {:08X}".format(file_id, added_value))

    def debit_value(self, file_id, value_decrease):
        """Decrease stored value.

        :param file_id: (byte)

        :param value_decrease:  (int, 32 bit) How much we reduce from existing value

        Example

        ::

            class BurnerScreen(Screen):
                '''Continuously keep decreasing credits on the card.'''

                def on_enter(self):
                    Logger.debug("Entering burner screen")
                    nfc_controller.callback = self.detect_new_tag
                    self.timer = None
                    self.device = None

                def detect_new_tag(self, tag):

                    Logger.debug("Detected tag %s", tag)
                    self.tag = tag
                    self.device = deviceDep.get(tag)
                    self.device.connect()
                    self.start_burner_cycle()

                def start_burner_cycle(self):
                    Logger.debug("Starting next burner cycle")
                    self.timer = Timer(0.3, self.burn)
                    self.timer.start()

                def burn(self):

                    Logger.debug("Running burner cycle")

                    try:
                        if not self.device.isConnected():
                            # We have lost the tag
                            return

                        desfire = DESFire(self.device, Logger)
                        desfire.select_application(XXX_APP_ID)

                        desfire.debit_value(XXX_FILE_STORED_VALUE, 1)
                        new_value = desfire.get_value(XXX_FILE_STORED_VALUE)
                        desfire.commit()

                        # Show how much value we have after burn
                        self.value.text = "%d" % new_value

                        # Do next tick
                        self.start_burner_cycle()

                    except Exception as e:
                        # Most likely exception from device tag communications, tag moved away during communications
                        tb = traceback.format_exc()
                        Logger.exception(str(e))
                        Logger.exception(tb)
                    finally:
                        # Tell pyjnius we are done with this thread
                        jnius.detach()


                def cancel(self):
                    self.close()

                def close(self):

                    if self.device:
                        self.device.close()

                    # jnius threads are not cancellable
                    # if self.timer:
                    #    self.timer.cancel()

                    nfc_controller.callback = None
                    self.manager.switch_to(NFCScreen())
        """
        value = dword_to_byte_array(value_decrease)

        apdu_command = self.wrap_command(0xdc, [file_id] + value)
        self.communicate(apdu_command, "Debiting file {:02X} value {:08X}".format(file_id, value_decrease))

    def commit(self):
        """Commit all write changes to the card.

        Example

        ::

            def top_up(self, tag, added_value):
                device = deviceDep.get(tag)
                device.connect()

                desfire = DESFire(device, Logger)

                try:

                    desfire.select_application(XXX_APP_ID)
                    old_value = desfire.get_value(0x01)
                    desfire.credit_value(0x01, added_value)
                    desfire.commit()
                    return old_value
                finally:
                    device.close()


        """
        apdu_command = self.wrap_command(0xc7)
        self.communicate(apdu_command, "Commiting file changes")

    def delete_file(self, file_id):
        """Delete a file.

        :param file_id: byte
        """

        apdu_command = self.wrap_command(0xDF, [file_id])
        self.communicate(apdu_command, "Deleting file {:02X}".format(file_id))

    def create_value_file(self, file_id, communication_settings, access_permissions, min_value, max_value, current_value, limited_credit_enabled):
        """Create a new value file.

        :param file_id: (byte)

        :param communication_settings: (byte) See FILE_COMMUNICATION

        :param access_permissions: (word) 0xeeee Everybody has read write access

        :param current_value: (dword)

        :param max_value: (dword)

        :param min_value: (dword)

        :param limited_credit_enabled: (byte) Allows limited increase in value file without having full credit permission.

        Example

        ::

            def write_card(self, tag, value):
                device = deviceDep.get(tag)
                device.connect()

                desfire = DESFire(device, Logger)

                try:
                    desfire.select_application(XXX_APP_ID)

                    file_ids = desfire.get_file_ids()
                    if XXX_FILE_STORED_VALUE in file_ids:
                        old_value = desfire.get_value(XXX_FILE_STORED_VALUE)
                        desfire.delete_file(XXX_FILE_STORED_VALUE)
                    else:
                        old_value = None

                    desfire.create_value_file(file_id=XXX_FILE_STORED_VALUE, communication_settings=0x00, access_permissions=0xeeee, min_value=0, max_value=1000000, current_value=value, limited_credit_enabled=0)

                    return old_value
                finally:
                    device.close()
        """

        parameters = [file_id]

        assert communication_settings in FILE_COMMUNICATION
        parameters += [communication_settings]
        parameters += [access_permissions & 0xff, access_permissions >> 8]
        parameters += dword_to_byte_array(min_value)
        parameters += dword_to_byte_array(max_value)
        parameters += dword_to_byte_array(current_value)
        parameters += [limited_credit_enabled]

        apdu_command = self.wrap_command(0xcc, parameters)
        self.communicate(apdu_command, "Creating value file {:02X}".format(file_id))

    def read_linear_record_file(self, file_id, offset_in_records, length_in_records):
        """Read all records of a linear record file.

        :param file_id: File id, 8-bit int
        :param offset_in_records: First record to read, 16-bit int
        :param length_in_records: Number of records to read, 16-bit int
        :return: File data as bytes
        """

        raise NotImplementedError()

        # This will simply read the whole file once
        # parameters = [file_id]
        # parameters = [file_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        # # parameters += word_to_byte_array(offset_in_records)
        # # parameters += [0x00]  # 24-bit
        # # parameters += word_to_byte_array(length_in_records)
        # # parameters += [0x00]  # 24-bit
        #
        # apdu_command = self.wrap_command(0xbb, parameters)
        # return self.communicate(apdu_command, "Reading bytes from offset {} length {} in a line record file file {:02X}".format(offset_in_records, length_in_records, file_id))

    def read_data_file(self, file_id):
        """Read standard data file.

        If the data file is unwritten (no single write since card format) it should return 0x00 as data after format.

        Example::

            def write_test(desfire):
                '''Write a long data file to see card write functions work.

                Assume the card is formatted with 7000 bytes test file. If we do not fill in file bytes during write, then the next read will reflect back whatever garbage we left there unwritten.
                '''
                logger.debug("Writing and reading back a test file")
                desfire.select_application(XXX_APP_ID)
                file_settings = desfire.get_file_settings(XXX_BACKCHANNEL_FILE)
                logger.debug("File settings info %s", file_settings)

                data = [0xff]
                data += [0xaa] * 4000
                data += [0xbb]
                desfire.write_data_file(XXX_BACKCHANNEL_FILE, data)

                # Standard files do not have any kind of commit of write corruption or commit support,
                # so no need to commit here

                # Now read it back
                read_back_data = desfire.read_data_file(XXX_BACKCHANNEL_FILE)
                assert len(read_back_data) == 7000

                assert data == read_back_data[0:4002]

        :param file_id: File id to read, 8-bit int
        :return: List of bytes
        """
        parameters = [file_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

        start_time = time.time()
        apdu_command = self.wrap_command(0xbd, parameters)

        buffer = self.communicate(apdu_command, "Reading data file {:02X}".format(file_id))

        duration = time.time() - start_time
        self.logger.debug("Finished reading %d bytes in %f seconds", len(buffer), duration)

        return buffer

    def write_linear_record_file_record(self, file_id, offset_in_records, length_in_records, data):
        """Write n records in a linear record file.

        :param file_id: File id, 8-bit int
        :param offset_in_records: First record to read, 16-bit int
        :param length_in_records: Number of records to read, 16-bit int
        :param data: bytes or list of bytes
        :return: File data as bytes
        """
        raise NotImplementedError()

        # parameters = [file_id]
        # parameters += word_to_byte_array(offset_in_records)
        # parameters += [0x00]  # 24bit
        # parameters += word_to_byte_array(length_in_records)
        # parameters += [0x00]  # 24bit
        # #parameters += [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        #
        # data_pointer = 0
        # max_apdu_write_length = 52
        #
        # while data_pointer < len(data):
        #     chunk = data[data_pointer:data_pointer + max_apdu_write_length]
        #     parameters = parameters + chunk
        #     apdu_command = self.wrap_command(0x3d, parameters)
        #     self.communicate(apdu_command, "Writing line record file file {:02X} offset {} length {} current write pointer {}".format(file_id, offset_in_records, length_in_records, data_pointer))

    def write_data_file(self, file_id, data):
        """Write the data to a standard data file.

        :param file_id: File number to write, 8-bit int
        :param data: Data as bytes or array of bytes
        """

        parameters = [file_id]
        parameters += word_to_byte_array(0)  # offset 0
        parameters += [0x00]  # 24-bit
        parameters += word_to_byte_array(len(data))
        parameters += [0x00]  # 24-bit

        data_pointer = 0
        max_apdu_write_length = 47  # Actual max value found by experimenting
        command = 0x3d  # WRITE DATA
        cycles = 0
        start_time = time.time()

        self.logger.debug("Attempting to write %d bytes to a data file %02x", len(data), file_id)

        while data_pointer < len(data):
            chunk = data[data_pointer:data_pointer + max_apdu_write_length]
            parameters = parameters + chunk
            apdu_command = self.wrap_command(command, parameters)
            self.communicate(apdu_command, "Writing line record file file {:02X}, current command {:02X} write pointer: {}".format(file_id, command, data_pointer), allow_continue_fallthrough=True)

            data_pointer += max_apdu_write_length

            # Use different parameters for the 2nd ... nth write cycle
            command = 0xaf  # CONTINUE
            max_apdu_write_length = 54
            parameters = []
            cycles += 1

        duration = time.time() - start_time
        self.logger.debug("Finished writing %d bytes in %d commands and %f seconds", len(data), cycles, duration)

    def format(self):
        """Format the card.

        .. warn ::

            This function is a stub and not finished.

        .. note ::

            You need to authenticate with the master key first.

        All application are deleted and all files within them. The PICC Master Keyand the PICC Master Key settings keep their currently set values
        """

        raise NotImplementedError("This has not been tested out yet")

        # Example format trace
        """
        23:21 Card Saved Successfully
        23:21 Data written to Card OK
        23:21 New Session B9 FE E5 89 CF F7 2F 60 B9 FE E5 89 CF F7 2F 60
        23:21 Authenticate TDES Key#00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        23:21 Aid 000000 selected OK
        23:21 APP (121314) Keys Saved OK
        23:21 New Session 74 D0 AD AC 10 AC C3 93 74 D0 AD AC 10 AC C3 93
        23:21 Authenticate TDES Key#00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        23:21 Aid 121314 selected OK
        23:21 New Session 43 2B EC 76 D0 15 F0 5B 43 2B EC 76 D0 15 F0 5B
        23:21 Authenticate TDES Key#00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        23:21 Aid 121314 selected OK
        23:21 Create APP 121314 OK
        23:21 Aid 000000 selected OK
        23:21 New Session 83 48 66 D0 68 DA 3F 6C 83 48 66 D0 68 DA 3F 6C
        23:21 Authenticate TDES Key#00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        23:21 Aid 000000 selected OK
        23:21 Format Card Command Status OK
        23:21 Card Authenticated OK
        23:21 New Session 55 12 0F E9 51 9C 5E C5 55 12 0F E9 51 9C 5E C5
        23:21 Authenticate TDES Key#00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        23:21 Aid 000000 selected OK
        23:21 Formatting Card....
        """


        apdu_command = self.wrap_command(0xFC, [])
        self.communicate(apdu_command, "Formatting card")

    def create_application(self, app_id, key_settings_1, key_settings_2):
        """Creates a new application.

        .. warn ::

            This function is a stub and not finished.

        https://www.mifare.net/files/advanced_javadoc/com/nxp/nfclib/desfire/DESFire.html#createApplication(byte[],%20byte,%20byte)

        :param app_id: 24-bit application id

        :param key_settings_1: byte

        :param key_settings_2: byte
        """

        raise NotImplementedError("This has not been tested out yet")

        parameters = [
            (app_id >> 16) & 0xff,
            (app_id >> 8) & 0xff,
            (app_id >> 0) & 0xff,
            key_settings_1,
            key_settings_2,
        ]

        # CREATE_APPLICATION((byte) 0xCA),
        apdu_command = self.wrap_command(0xCA, parameters)
        self.communicate(apdu_command, "Creating application {:06X}".format(app_id))

