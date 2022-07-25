package com.oxande.ssh;

import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Packet;
import com.jcraft.jsch.UserInfo;

import javax.crypto.ShortBufferException;
import java.io.IOException;

public interface ISession {
  void write(Packet p) throws JSchException, IOException, ShortBufferException;
  UserInfo getUserInfo();

  Packet getPacket();

  String getUserName();

  String getConfig(String key);
}
