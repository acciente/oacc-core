package com.acciente.oacc;

import java.io.Serializable;

class SysPermission implements Serializable {

	private static final long serialVersionUID = 1L;

	private final long   systemPermissionId;
   private final String permissionName;

   SysPermission(int systemPermissionId, String permissionName) {
      if (systemPermissionId == 0) {
         throw new IllegalArgumentException("System permission ID must be non-zero");
      }

      if (!permissionName.startsWith("*")) {
         throw new IllegalArgumentException("System permission names MUST start with *");
      }

      this.systemPermissionId = systemPermissionId;
      this.permissionName = permissionName.intern();
   }

   public long getSystemPermissionId() {
      return systemPermissionId;
   }

   public String getPermissionName() {
      return permissionName;
   }

   @Override
   public int hashCode() {
      int result = (int) (systemPermissionId ^ (systemPermissionId >>> 32));
      result = 31 * result + permissionName.hashCode();
      return result;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      }
      if (o == null || getClass() != o.getClass()) {
         return false;
      }

      SysPermission that = (SysPermission) o;

      if (systemPermissionId != that.systemPermissionId) {
         return false;
      }
      if (!permissionName.equals(that.permissionName)) {
         return false;
      }

      return true;
   }
}
