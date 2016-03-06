"""Mifare DESFire communication protocol for Python.

Copyright 2016 Mikko Ohtamaa, https://opensourcehacker.com

Licensed under BSD license: https://opensource.org/licenses/BSD-3-Clause

"""
from __future__ import print_function


def byte_array_to_byte_string(bytes):
    s = "".join([chr(b) for b in bytes])
    return s


def byte_array_to_hex(bytes):
    s = byte_array_to_byte_string(bytes)
    return s.encode("hex")


def byte_string_to_byte_array(s):
    return [ord(c) for c in s]


def hex_array_to_byte_string(hex_array):
    return "".join(chr(c) for c in hex_array)


def dword_to_byte_array(value):
    return [(value & 0xff), (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24),]


class DESFireCommunicationError(Exception):
    """Command could not be completed.

    https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java
    """

    ERRORS = {
        0x9d: "Permission denied",
        0x1c: "Limited credit",
        0xae: "Authentication error",
        0x7e: "Length error when sending the command",
        0x0c: "No changes",
        0xf0: "File not found"
    }


class DESFire(object):
    """MIFare DEefire EV1 communication protocol for NFC cards.

    For DESFire overview:

    * http://www.slideshare.net/ashu4india/mifare-des-fire-pres

    For list of DESFire commands see:

    * https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesFireInstruction.java

    * https://www.mifare.net/files/advanced_javadoc/com/nxp/nfclib/desfire/DESFire.html

    * https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java
    """

    FILE_TYPES = {
        0x00: "Standard Data Files",
        0x01: "Backup Data Files",
        0x02: "Value Files with Backup",
        0x03: "Linear Record Files with Backup",
        0x04: "Cyclic Record Files with Backup",
    }

    FILE_COMMUNICATION = {
        0x00: "Plain communication",
        0x01: "Plain communication secured by DES/3DES MACing",
        0x03: "Fully DES/3DES enciphered communication",
    }

    def __init__(self, iso, logger):
        """

        Parameters
        ----------
        iso Android android.nfc.tech.IsoDep interface
        logger Communications logging

        Returns
        -------

        """
        self.iso = iso
        self.logger = logger

    def communicate(self, apdu_cmd, description):
        """Communicate with NFC tag.

        Parameters
        ----------
        apdu_cmd APDU command as array of bytes
        description Information for logging purposes

        Returns
        -------

        APDU response as array of bytes

        """
        apdu_cmd_hex = [hex(c) for c in apdu_cmd]
        self.logger.info("Running APDU command %s, sending: %s", description, apdu_cmd_hex)

        resp = self.iso.transceive(apdu_cmd)
        self.logger.info("Received APDU response: %s", byte_array_to_hex(resp))

        if resp[-2] != 0x91:
            raise DESFireCommunicationError("Received invalid response for: {}".format(description))

        status = resp[-1]

        # Possible status words: https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireStatusWord.java

        # Check for known erors
        error_msg = DESFireCommunicationError.ERRORS.get(status)
        if error_msg:
            raise DESFireCommunicationError(error_msg)

        if status == 0xaf:
            # TODO: Additional framing
            pass
        elif status != 0x00:
            raise DESFireCommunicationError("Error {:02x} when communicating".format(status))

        # This will un-memoryview this object as there seems to be some pyjnius
        # bug getting this corrupted down along the line
        unframed = list(resp[0:-2])

        self.logger.info("Unframed response: %s", byte_array_to_hex(unframed))

        return unframed

    def parse_application_list(self, resp):
        """Handle response for command 0x6a list applications.

        DESFire application ids are 24-bit integers.

        Parameters
        ----------
        resp DESFire response as byte array

        Returns
        -------

        List of parsed application ids

        """
        pointer = 0
        apps = []
        self.logger.info("Resp is %s", resp)
        self.logger.info("Resp is %s", byte_array_to_hex(resp))
        while pointer < len(resp):
            app_id = (resp[pointer] << 16) + (resp[pointer+1] << 8) + resp[pointer+2]
            self.logger.info("Reading %d %08x", pointer, app_id)
            apps.append(app_id)
            pointer += 3

        return apps

    def get_applications(self):
        """Get all applications listed in Desfire root."""

        # https://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
        cmd = self.wrap_command(0x6a)
        resp = self.communicate(cmd, "Read applications")
        self.logger.info("Foobar %s", byte_array_to_hex(resp))
        apps = self.parse_application_list(resp)
        return apps

    def wrap_command(self, command, parameters=None):
        """Wrap command to native DES framing.

        https://github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L129
        """
        if parameters:
            return [0x90, command, 0x00, 0x00, len(parameters)] + parameters + [0x00]
        else:
            return [0x90, command, 0x00, 0x00, 0x00]

    def select_application(self, app_id):

        # https://github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L53
        parameters = [
            (app_id >> 16) & 0xff,
            (app_id >> 8) & 0xff,
            (app_id >> 0) & 0xff,
        ]

        apdu_command = self.wrap_command(0x5a, parameters)

        resp = self.communicate(apdu_command, "Selecting application {:06X}".format(app_id))

    def get_file_ids(self):
        # https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesfireApplet.java#L484
        apdu_command = self.wrap_command(0x6f)
        resp = self.communicate(apdu_command, "Listing files")
        # Byte ids are directly the ids of files
        return resp

    def authenticate(self, app_id, key_id, private_key=[0x00] * 16):
        """Hacked together Android only DESFire authentication.

        Desfire supports multiple authentication modes, see:

        * https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesFireInstruction.java

        Here we use legacy authentication (0xa0)
        """

        from jnius import autoclass
        from jnius import cast

        Cipher = autoclass("javax.crypto.Cipher")
        SecretKeySpec = autoclass("javax.crypto.spec.SecretKeySpec")
        SecretKeyFactory = autoclass("javax.crypto.SecretKeyFactory")
        IvParameterSpec = autoclass("javax.crypto.spec.IvParameterSpec")
        DESKeySpec = autoclass("javax.crypto.spec.DESKeySpec")
        DESedeKeySpec = autoclass("javax.crypto.spec.DESedeKeySpec")
        String = autoclass("java.lang.String")

        apdu_command = self.wrap_command(0x0a, [key_id])
        resp = self.communicate(apdu_command, "Authenticating application {:06X}".format(app_id))

        # http://java-card-desfire-emulation.googlecode.com/svn/trunk/java-card-desfire-emulation/Credit%20DESfire%20App/src/credit/DESfireApi.java
        # http://mrbigzz.blogspot.com/2014/01/android-desfire-authentication.html
        random_b_encrypted = list(resp)
        assert len(random_b_encrypted) == 8

        #bytes = String("xxxxXXXXxxxxXXXX").getBytes()
        #des_key_spec = DESedeKeySpec(bytes)

        cipher = Cipher.getInstance("DESede/ECB/NoPadding","BC")

        secret_key_spec = SecretKeySpec(private_key, "DESede")
        secret_key = cast("java.security.Key", secret_key_spec)

        cipher.init(Cipher.DECRYPT_MODE, secret_key)
        random_b_decrypted = list(cipher.doFinal(random_b_encrypted))
        self.logger.info("Decrypted random B %s", byte_array_to_hex(random_b_decrypted))

        # Let's pick up by fire dice
        # This let's us skip one XOR'ing
        # http://java-card-desfire-emulation.googlecode.com/svn/trunk/java-card-desfire-emulation/Credit%20DESfire%20App/src/credit/DESfireApi.java
        random_a = [0x00] * 8

        cipher.init(Cipher.ENCRYPT_MODE, secret_key)

        rotated_b = random_b_decrypted[1:] + random_b_decrypted[0:1]
        cipher_text = list(cipher.update(random_a)) + list(cipher.doFinal(rotated_b))

        self.logger.info("Sending in cipher text %s", byte_array_to_hex(cipher_text))
        assert len(cipher_text) == 16

        apdu_command = self.wrap_command(0xaf, cipher_text)
        resp = self.communicate(apdu_command, "Sending auth response")

        # http://stackoverflow.com/questions/14319321/how-can-i-do-native-authentication-in-desfire-ev1
        # http://stackoverflow.com/questions/17111451/what-kind-of-block-format-is-the-desfire-authentication-message
        # https://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
        # http://stackoverflow.com/questions/14117025/des-send-and-receive-modes-for-desfire-authentication

    def read_file(self, file_id):
        """Read one DESFire file.

        Parameters
        ----------
        file_id File id as a byte

        Returns
        -------

        File data
        """
        apdu_command = self.wrap_command(0x8d, [file_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        resp = self.communicate(apdu_command, "Reading file {:02X}".format(file_id))

        return resp[1:]

    def get_file_settings(self, file_id):
        """Get DESFire file settings.

        Parameters
        ----------
        file_id File id as a byte

        Returns
        -------

        File description dict.
        """
        apdu_command = self.wrap_command(0xf5, [file_id])
        resp = self.communicate(apdu_command, "Reading file description {:02X}".format(file_id))

        file_desc = {
            "type": self.FILE_TYPES[resp[0]],
            "communication": self.FILE_COMMUNICATION[resp[1]],
            "rw_flags": resp[2:4],
            "length": resp[4] | (resp[5] << 8) | (resp[6] << 16)
        }

        return file_desc

    def get_value(self, file_id):
        """Get stored value.

        Parameters
        ----------
        file_id

        Returns
        -------

        Integer.
        """
        apdu_command = self.wrap_command(0x6c, [file_id])
        resp = self.communicate(apdu_command, "Reading value {:02X}".format(file_id))
        # TODO: Not sure about the order of higher bits (32 bit?)
        return (resp[3] << 24) | (resp[2] << 16) | (resp[1] << 8) | resp[0]

    def credit_value(self, file_id, added_value):
        """Increase stored value.

        Parameters
        ----------
        file_id (byte)

        added_value (int, 32 bit) Value to be added to the current value
        """

        value = dword_to_byte_array(added_value)

        apdu_command = self.wrap_command(0x0c, [file_id] + value)
        self.communicate(apdu_command, "Crediting file {:02X} value {:08X}".format(file_id, added_value ))

    def debit_value(self, file_id, value_decrease):
        """Decrease stored value.

        Parameters
        ----------
        file_id (byte)

        value_decrease (int, 32 bit) How much we reduce from existing value

        Example
        -------

        ::

            class BurnerScreen(Screen):
                '''Continuously keep decreasing credits on the card.'''

                def on_enter(self):
                    Logger.info("Entering burner screen")
                    nfc_controller.callback = self.detect_new_tag
                    self.timer = None
                    self.iso = None

                def detect_new_tag(self, tag):

                    Logger.info("Detected tag %s", tag)
                    self.tag = tag
                    self.iso = IsoDep.get(tag)
                    self.iso.connect()
                    self.start_burner_cycle()

                def start_burner_cycle(self):
                    Logger.info("Starting next burner cycle")
                    self.timer = Timer(0.3, self.burn)
                    self.timer.start()

                def burn(self):

                    Logger.info("Running burner cycle")

                    try:
                        if not self.iso.isConnected():
                            # We have lost the tag
                            return

                        desfire = DESFire(self.iso, Logger)
                        desfire.select_application(WATTCOIN_APP_ID)

                        desfire.debit_value(WATTCOIN_FILE_STORED_VALUE, 1)
                        new_value = desfire.get_value(WATTCOIN_FILE_STORED_VALUE)
                        desfire.commit()

                        # Show how much value we have after burn
                        self.value.text = "%d" % new_value

                        # Do next tick
                        self.start_burner_cycle()

                    except Exception as e:
                        # Most likely exception from ISO tag communications, tag moved away during communications
                        tb = traceback.format_exc()
                        Logger.exception(str(e))
                        Logger.exception(tb)
                    finally:
                        # Tell pyjnius we are done with this thread
                        jnius.detach()


                def cancel(self):
                    self.close()

                def close(self):

                    if self.iso:
                        self.iso.close()

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
        -------

        ::

            def top_up(self, tag, added_value):
                iso = IsoDep.get(tag)
                iso.connect()

                desfire = DESFire(iso, Logger)

                try:

                    desfire.select_application(WATTCOIN_APP_ID)
                    old_value = desfire.get_value(0x01)
                    desfire.credit_value(0x01, added_value)
                    desfire.commit()
                    return old_value
                finally:
                    iso.close()


        """
        apdu_command = self.wrap_command(0xc7)
        self.communicate(apdu_command, "Commiting file changes")

    def delete_file(self, file_id):
        """Delete a file."""

        apdu_command = self.wrap_command(0xDF, [file_id])
        self.communicate(apdu_command, "Deleting file {:02X}".format(file_id))

    def create_value_file(self, file_id, communication_settings, access_permissions, min_value, max_value, current_value,limited_credit_enabled):
        """Create a new value file.

        Parameters
        ----------
        file_id (byte)

        communication_settings (byte) See FILE_COMMUNICATION

        access_permissions (word) 0xeeee Everybody has read write access

        current_value (dword)

        max_value (dword)

        min_value (dword)

        limited_credit_enabled (byte) Allows limited increase in value file without having full credit permission.

        Example
        -------

        ::

            def write_card(self, tag, value):
                iso = IsoDep.get(tag)
                iso.connect()

                desfire = DESFire(iso, Logger)

                try:
                    desfire.select_application(WATTCOIN_APP_ID)

                    file_ids = desfire.get_file_ids()
                    if WATTCOIN_FILE_STORED_VALUE in file_ids:
                        old_value = desfire.get_value(WATTCOIN_FILE_STORED_VALUE)
                        desfire.delete_file(WATTCOIN_FILE_STORED_VALUE)
                    else:
                        old_value = None

                    desfire.create_value_file(file_id=WATTCOIN_FILE_STORED_VALUE, communication_settings=0x00, access_permissions=0xeeee, min_value=0, max_value=1000000, current_value=value, limited_credit_enabled=0)

                    return old_value
                finally:
                    iso.close()
        """

        parameters = [file_id]

        assert communication_settings in self.FILE_COMMUNICATION
        parameters += [communication_settings]
        parameters += [access_permissions & 0xff, access_permissions >> 8]
        parameters += dword_to_byte_array(min_value)
        parameters += dword_to_byte_array(max_value)
        parameters += dword_to_byte_array(current_value)
        parameters += [limited_credit_enabled]

        apdu_command = self.wrap_command(0xcc, parameters)
        self.communicate(apdu_command, "Creating value file {:02X}".format(file_id))
