package com.acciente.oacc.sql.internal.encryptor;

import java.util.Arrays;
import java.util.List;

/**
 * Internally used helper class to get an instance of the {@link PasswordEncryptor} identified
 * by the name of the {@link PasswordEncryptor}. This is where the NAME constant that is expected to
 * be defined in every {@link PasswordEncryptor} implementation is used.
 */
public class PasswordEncryptors {
   public static PasswordEncryptor getPasswordEncryptor(String encryptorName) {
      if (encryptorName == null) {
         throw new IllegalArgumentException("Encryptor name cannot be null");
      }

      if (encryptorName.equalsIgnoreCase(JasyptPasswordEncryptor.NAME)) {
         return JasyptPasswordEncryptor.getPasswordEncryptor();
      }

      throw new IllegalArgumentException("Encryptor name " + encryptorName + " not recognized");
   }

   public static List<String> getSupportedEncryptorNames() {
      return Arrays.asList(JasyptPasswordEncryptor.NAME);
   }
}
