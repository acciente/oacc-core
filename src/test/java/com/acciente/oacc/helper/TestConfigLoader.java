/*
 * Copyright 2009-2018, Acciente LLC
 *
 * Acciente LLC licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.acciente.oacc.helper;

import com.acciente.oacc.encryptor.PasswordEncryptor;
import com.acciente.oacc.encryptor.bcrypt.BCryptPasswordEncryptor;
import com.acciente.oacc.encryptor.jasypt.JasyptPasswordEncryptor;
import com.acciente.oacc.sql.SQLProfile;

import javax.sql.DataSource;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Properties;

public class TestConfigLoader {
   private static DataSource        dataSource;
   private static Boolean           isDatabaseCaseSensitive;
   private static SQLProfile        sqlProfile;
   private static String            databaseSchema;
   private static PasswordEncryptor passwordEncryptor;
   private static char[]            oaccRootPwd;

   public static final String PROP_DATA_SOURCE_CLASS = "dataSourceClass";
   public static final String PROP_SQL_PROFILE       = "sqlProfile";
   public static final String PROP_DB_SCHEMA         = "dbSchema";
   public static final String PROP_PWD_ENCRYPTOR     = "pwdEncryptor";
   public static final String PROP_OACC_ROOT_PWD     = "oaccRootPwd";

   static {
      try {
         final String dbConfigFilename = System.getProperty("dbconfig");
         if (dbConfigFilename == null) {
            throw new RuntimeException(
                  "system property 'dbconfig' not specified; please specify VM parameter with -Ddbconfig=<filename> (example: -Ddbconfig=dbconfig_postgresql.properties)");
         }

         final ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
         final InputStream inputStream = contextClassLoader.getResourceAsStream(dbConfigFilename);
         if (inputStream == null) {
            throw new RuntimeException("could not find resource " + dbConfigFilename);
         }

         final Properties properties = new Properties();
         properties.load(inputStream);
         final Class<?> dataSourceClass = Class.forName(properties.getProperty(PROP_DATA_SOURCE_CLASS));
         final DataSource vendorSpecificDataSource = (DataSource) dataSourceClass.newInstance();

         final String sqlTypeName = properties.getProperty(PROP_SQL_PROFILE);
         if (sqlTypeName==null) {
            throw new RuntimeException("no " + PROP_SQL_PROFILE
                                             + " property specified in database configuration property file");
         }
         sqlProfile = SQLProfile.valueOf(sqlTypeName);

         for (String propertyName : properties.stringPropertyNames()) {
            if (!(PROP_DATA_SOURCE_CLASS.equals(propertyName)
                  || PROP_SQL_PROFILE.equals(propertyName)
                  || PROP_DB_SCHEMA.equals(propertyName)
                  || PROP_PWD_ENCRYPTOR.equals(propertyName)
                  || PROP_OACC_ROOT_PWD.equals(propertyName))) {
               setDataSourceProperty(vendorSpecificDataSource, propertyName, properties.getProperty(propertyName));
            }
         }
         dataSource = vendorSpecificDataSource;
         databaseSchema = properties.getProperty(PROP_DB_SCHEMA);
         if (properties.getProperty(PROP_OACC_ROOT_PWD) != null)
         {
            oaccRootPwd = properties.getProperty(PROP_OACC_ROOT_PWD).toCharArray();
         }
         isDatabaseCaseSensitive = CaseSensitiveChecker.isDatabaseCaseSensitive(dataSource);

         // set password encryptor
         final String pwdEncryptor = properties.getProperty(PROP_PWD_ENCRYPTOR);
         if (pwdEncryptor == null) {
            throw new RuntimeException("no " + PROP_PWD_ENCRYPTOR
                                             + " property specified in database configuration property file");
         }
         passwordEncryptor = getPasswordEncryptor(pwdEncryptor);
      }
      catch (Exception e) {
         throw new RuntimeException(e);
      }
   }

   private static PasswordEncryptor getPasswordEncryptor(String encryptorName) {
      if (encryptorName == null) {
         throw new IllegalArgumentException("Encryptor name cannot be null");
      }

      if (encryptorName.equalsIgnoreCase(BCryptPasswordEncryptor.NAME)) {
         return BCryptPasswordEncryptor.newInstance(4);
      }

      if (encryptorName.equalsIgnoreCase(JasyptPasswordEncryptor.NAME)) {
         return JasyptPasswordEncryptor.newInstance("SHA-256", 100000, 16);
      }

      throw new IllegalArgumentException("Encryptor name " + encryptorName + " not recognized");
   }

   private static void setDataSourceProperty(DataSource vendorSpecificDataSource,
                                             String propertyName,
                                             String valueAsString) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
      Integer valueAsInteger;
      Boolean valueAsBoolean = null;

      try {
         valueAsInteger = Integer.parseInt(valueAsString);
         valueAsString = null;
      }
      catch (NumberFormatException e) {
         valueAsInteger = null;
      }

      if (valueAsInteger == null && valueAsString != null) {
         final String trimmedAndLowerCasedValue = valueAsString.trim().toLowerCase();
         if (trimmedAndLowerCasedValue.equals("true")){
            valueAsBoolean = Boolean.TRUE;
            valueAsString = null;
         }
         else if (trimmedAndLowerCasedValue.equals("false")){
            valueAsBoolean = Boolean.FALSE;
            valueAsString = null;
         }
      }

      final String methodName = "set"
            + propertyName.substring(0, 1).toUpperCase()
            + propertyName.substring(1);
      final Method setMethod
            = vendorSpecificDataSource.getClass().getMethod(methodName,
                                                            valueAsInteger != null
                                                            ? int.class
                                                            : valueAsBoolean != null
                                                              ? boolean.class
                                                              : String.class);
      setMethod.invoke(vendorSpecificDataSource,
                       valueAsInteger!=null ? valueAsInteger : valueAsBoolean!=null ? valueAsBoolean : valueAsString);
   }

   public static SQLProfile getSQLProfile() {
      return sqlProfile;
   }

   public static DataSource getDataSource() {
      return dataSource;
   }

   public static String getDatabaseSchema() {
      return databaseSchema;
   }

   public static char[] getOaccRootPassword() {
      return oaccRootPwd;
   }

   public static boolean isDatabaseCaseSensitive() {
      return isDatabaseCaseSensitive;
   }

   public static PasswordEncryptor getPasswordEncryptor() {
      return passwordEncryptor;
   }
}
