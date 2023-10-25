/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.example;

import io.airlift.slice.Slice;
import io.trino.spi.function.Description;
import io.trino.spi.function.ScalarFunction;
import io.trino.spi.function.SqlNullable;
import io.trino.spi.function.SqlType;
import io.trino.spi.type.StandardTypes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.logging.Logger;

import static io.airlift.slice.Slices.utf8Slice;
import static io.trino.spi.type.StandardTypes.VARCHAR;

public class EncryptDecryptFunction
{
    Logger logger;
    private EncryptDecryptFunction()
    {}
    private static final String SALT = "56c6b89e-00e1-4fef-8267-2b6837f0e721";
    private static final String SECRET_KEY = "469edc2c-8664-4473-aa15-3935af14fd0a"; //"testing";
    private static final String SECRET_KEY_ALGO = "PBKDF2WithHmacSHA512";
    private static final int ITERATION_COUNT = 200000;
    private static final int KEY_LENGTH = 256;
    private static final String AES = "AES";
    private static final String PADDING = "AES/CBC/PKCS5Padding";
    private static final byte[] IV = {32, 34, 55, 54, 23, 56, 86, 84, 75, 33, 85, 32, 42, 14, 65, 75};

    @Description("Encryption for string data type")
    @ScalarFunction("encrypt_string")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt_string(@SqlType(StandardTypes.VARCHAR) Slice value)
    {
        return utf8Slice(encryptString(value.toStringUtf8()));
    }

    public static String encryptString(String strToEncrypt)
    {
        String encryptedStr = "";
        if (strToEncrypt != null && !strToEncrypt.isBlank()) {
            try {
                IvParameterSpec ivspec = new IvParameterSpec(IV);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGO);
                KeySpec spec =
                        new PBEKeySpec(
                                SECRET_KEY.toCharArray(), SALT.getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, KEY_LENGTH);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), AES);
                Cipher cipher = Cipher.getInstance(PADDING);
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);
                encryptedStr = Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
            }
            catch (Exception e) {
                System.out.println("Error occurred while value encrypting :: " + e.getMessage());
                e.printStackTrace();
            }
        }
        else {
            throw new NullPointerException("Given value is null");
        }
        return encryptedStr;
    }

    @Description("Decryption function for string data type")
    @ScalarFunction("decrypt_string")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice decrypt_string(@SqlType(StandardTypes.VARCHAR) Slice value)
    {
        return utf8Slice(decryptString(value.toStringUtf8()));
    }

    public static String decryptString(@SqlType(StandardTypes.VARCHAR) String strToDecrypt)
    {
        String decryptedStr = null;
        if (strToDecrypt != null && !strToDecrypt.isBlank()) {
            try {
                IvParameterSpec ivspec = new IvParameterSpec(IV);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGO);
                KeySpec spec =
                        new PBEKeySpec(
                                SECRET_KEY.toCharArray(), SALT.getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, KEY_LENGTH);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), AES);
                Cipher cipher = Cipher.getInstance(PADDING);
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
                byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(strToDecrypt.getBytes(StandardCharsets.UTF_8)));
                decryptedStr = new String(bytes, StandardCharsets.UTF_8);
            }
            catch (Exception e) {
                System.out.println("Error occurred while value decrypting:: " + e.getMessage());
                e.printStackTrace();
            }
        }
        else {
            throw new NullPointerException("Given value is null");
        }
        return decryptedStr;
    }

    @ScalarFunction("encrypt_bool")
    @Description("Encryption for boolean data type")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt_bool(@SqlNullable @SqlType(StandardTypes.BOOLEAN) Boolean value)
    {
        return utf8Slice(encryptBoolean(value));
    }

    public static String encryptBoolean(@SqlNullable @SqlType(StandardTypes.BOOLEAN) Boolean value)
    {
        return encryptString(String.valueOf(value));
    }

    @ScalarFunction("decrypt_bool")
    @Description("Decryption for boolean data type")
    @SqlType(StandardTypes.BOOLEAN)
    @SqlNullable
    public static Boolean decrypt_bool(@SqlType(VARCHAR) Slice value)
    {
        return decryptBoolean(value.toStringUtf8());
    }

    public static Boolean decryptBoolean(String encryptedValue)
    {
        boolean value;
        try {
            value = Boolean.parseBoolean(decryptString(encryptedValue));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
        return value;
    }

    @ScalarFunction("encrypt_bigint")
    @Description("Encryption for bigint data type")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt_bigint(@SqlNullable @SqlType(StandardTypes.BIGINT) Long value)
    {
        return utf8Slice(encryptBigint(String.valueOf(value)));
    }

    public static String encryptBigint(String valueToEncrypt)
    {
        return encryptString(String.valueOf(valueToEncrypt));
    }

    @ScalarFunction("decrypt_bigint")
    @Description("Decryption for bigint data type")
    @SqlType(StandardTypes.BIGINT)
    @SqlNullable
    public static Long decrypt_bigint(@SqlType(VARCHAR) Slice value)
    {
        return EncryptDecryptFunction.decryptBigInt(value.toStringUtf8());
    }

    public static Long decryptBigInt(String strToDecrypt)
    {
        long value;
        try {
            value = Long.parseLong(decryptString(strToDecrypt));
        }
        catch (NumberFormatException e) {
            throw new RuntimeException(e);
        }
        return value;
    }

    @ScalarFunction("encrypt_int")
    @Description("Encryption for int data type")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt_int(@SqlNullable @SqlType(StandardTypes.INTEGER) Integer value)
    {
        return utf8Slice(encryptInteger(value));
    }

    public static String encryptInteger(Integer value)
    {
        return encryptString(String.valueOf(value));
    }

    @ScalarFunction("decrypt_int")
    @Description("Decryption for int data type")
    @SqlType(StandardTypes.INTEGER)
    @SqlNullable
    public static Integer decrypt_int(@SqlType(StandardTypes.VARCHAR) Slice value)
    {
        return decryptInteger(value.toStringUtf8());
    }

    public static Integer decryptInteger(String strToDecrypt)
    {
        int value;
        try {
            value = Integer.parseInt(decryptString(strToDecrypt));
        }
        catch (NumberFormatException e) {
            throw new RuntimeException(e);
        }
        return value;
    }

    @ScalarFunction("encrypt_decimal")
    @Description("Encryption for decimal data type")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt_decimal(@SqlNullable @SqlType(StandardTypes.DECIMAL) BigDecimal value)
    {
        return utf8Slice(encryptDecimal(value));
    }

    public static String encryptDecimal(@SqlNullable @SqlType(StandardTypes.DECIMAL) BigDecimal value)
    {
        return encryptString(String.valueOf(value));
    }

    @ScalarFunction("decrypt_decimal")
    @Description("Decryption for decimal data type")
    @SqlType(StandardTypes.DECIMAL)
    @SqlNullable
    public static BigDecimal decrypt_decimal(@SqlType(StandardTypes.VARCHAR) Slice strToDecrypt)
    {
        return decryptDecimal(strToDecrypt.toStringUtf8());
    }

    public static BigDecimal decryptDecimal(@SqlType(StandardTypes.VARCHAR) String strToDecrypt)
    {
        BigDecimal decimal = new BigDecimal(decryptString(strToDecrypt));
        return decimal;
    }

    @ScalarFunction("encrypt_double")
    @Description("Encryption for double data type")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt_double(@SqlNullable @SqlType(StandardTypes.DOUBLE) Double value)
    {
        return utf8Slice(encryptDouble(value));
    }

    public static String encryptDouble(@SqlNullable @SqlType(StandardTypes.DOUBLE) Double value)
    {
        return encryptString(String.valueOf(value));
    }

    @ScalarFunction("decrypt_double")
    @Description("Decryption for double data type")
    @SqlType(StandardTypes.DOUBLE)
    @SqlNullable
    public static Double decrypt_double(@SqlType(StandardTypes.VARCHAR) Slice strToDecrypt)
    {
        return decryptDouble(strToDecrypt.toStringUtf8());
    }

    public static Double decryptDouble(@SqlType(StandardTypes.VARCHAR) String strToDecrypt)
    {
        double value;
        try {
            value = Double.parseDouble(decryptString(strToDecrypt));
        }
        catch (NumberFormatException e) {
            throw new RuntimeException(e);
        }
        return value;
    }

    @ScalarFunction("encrypt_date")
    @Description("Encryption for date data type")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt_date(@SqlNullable @SqlType(StandardTypes.DATE) Long date)
    {
        return utf8Slice(encryptDate(date.toString()));
    }

    public static String encryptDate(String dateToEncrypt)
    {
        return encryptString(dateToEncrypt);
    }

    @ScalarFunction("decrypt_date")
    @Description("Decryption for date data type")
    @SqlType(StandardTypes.DATE)
    public static long decrypt_date(@SqlType(StandardTypes.VARCHAR) Slice value)
    {
        return decryptDate(value.toStringUtf8());
    }

    public static long decryptDate(String strToDecrypt)
    {
        LocalDate date;
        try {
            Long epochSecond = Long.valueOf(decryptString(strToDecrypt));
            date = LocalDate.ofInstant(Instant.ofEpochSecond(epochSecond), ZoneId.systemDefault());
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
        return date.atStartOfDay(ZoneId.systemDefault()).toEpochSecond();
    }

    @ScalarFunction("encrypt_timestamp")
    @Description("Encryption for timestamp data type")
    @SqlType(StandardTypes.VARCHAR)
    public static Slice encrypt_timestamp(@SqlNullable @SqlType(StandardTypes.TIMESTAMP) Long value)
    {
        System.out.println("TIMESTAMP value :: " + value);
        return utf8Slice(encryptDateTime(value.toString()));
    }

    public static String encryptDateTime(String value)
    {
        return encryptString(value);
    }

    @ScalarFunction("decrypt_timestamp")
    @Description("Decryption for timestamp data type")
    @SqlType(StandardTypes.TIMESTAMP)
    public static long decrypt_timestamp(@SqlType(StandardTypes.VARCHAR) Slice value)
    {
        return decryptDateTime(value.toStringUtf8());
    }

    public static long decryptDateTime(@SqlType(StandardTypes.VARCHAR) String strToDecrypt)
    {
        LocalDateTime dateTime;
        try {
            Long epochSecond = Long.valueOf(decryptString(strToDecrypt));
            dateTime = LocalDateTime.ofInstant(Instant.ofEpochSecond(epochSecond), ZoneId.systemDefault());
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
        return dateTime.atZone(ZoneId.systemDefault()).toEpochSecond();
    }

    @ScalarFunction("encrypt_timestamp_with_format")
    @Description("Encryption for timestamp data type")
    @SqlType(VARCHAR)
    public static Slice
    encrypt_timestamp_with_format(@SqlNullable @SqlType(StandardTypes.TIMESTAMP) Long value)
    {
        return utf8Slice(encryptDateTimeWithFormat(value));
    }

    public static String encryptDateTimeWithFormat(Long value)
    {
        LocalDateTime time = LocalDateTime.ofInstant(Instant.ofEpochSecond(value), ZoneId.systemDefault());
        System.out.println("Error occurred while value encrypting :: " + time);
        String formattedTimeStamp = time.format(DateTimeFormatter.ofPattern("yyyy-mm-dd hh:mm:ss.SSSSSS"));
        System.out.println("Error occurred while value encrypting :: " + formattedTimeStamp);
        return encryptString(formattedTimeStamp);
    }

    @ScalarFunction("decrypt_timestamp_with_format")
    @Description("Decryption for timestamp data type")
    @SqlType(StandardTypes.TIMESTAMP)
    public static long decrypt_timestamp_with_format(@SqlType(StandardTypes.VARCHAR) Slice value, @SqlType(StandardTypes.VARCHAR) Slice pattern)
    {
        return decryptDateTimeWithFormat(value.toStringUtf8(), pattern.toStringUtf8());
    }

    public static long decryptDateTimeWithFormat(String strToDecrypt, String pattern)
    {
        LocalDateTime formattedDateTime;
        try {
            formattedDateTime = LocalDateTime.parse(decryptString(strToDecrypt), DateTimeFormatter.ofPattern(pattern));
            System.out.println("formattedDateTime  :: " + formattedDateTime);
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
        return formattedDateTime.atZone(ZoneId.systemDefault()).toEpochSecond();
    }
}
