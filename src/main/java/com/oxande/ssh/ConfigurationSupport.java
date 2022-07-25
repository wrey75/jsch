package com.oxande.ssh;

import com.jcraft.jsch.ConfigRepository;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.IdentityRepository;
import com.jcraft.jsch.JSchException;

import java.lang.reflect.InvocationTargetException;

public interface ConfigurationSupport {

  /**
   * Get the configuration value.
   *
   * @return the configuration value
   */
  String getConfig(String key);

  HostKeyRepository getHostKeyRepository();

  default <T> T getConfigInstance(String key) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
    Class<T> c = (Class<T>) Class.forName(getConfig(key));
    return c.getDeclaredConstructor().newInstance();
  }

  ConfigRepository getConfigRepository();
  
  IdentityRepository getIdentityRepository();
  
  void addIdentity(String identity) throws JSchException;
  
  void addSession(ISession session);
  void removeSession(ISession session);
}
