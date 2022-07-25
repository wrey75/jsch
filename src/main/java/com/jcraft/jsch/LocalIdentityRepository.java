/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2012-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright 
     notice, this list of conditions and the following disclaimer in 
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package com.jcraft.jsch;

import com.jcraft.jsch2.ISecureChannel;

import java.util.List;
import java.util.Vector;

class LocalIdentityRepository implements IdentityRepository {
  private static final String NAME = "Local Identity Repository";

  private final List<Identity> identities = new Vector<>();
  private ISecureChannel jsch;

  public LocalIdentityRepository(ISecureChannel jsch){
    this.jsch = jsch;
  }

  @Override
  public String getName(){
    return NAME;
  }

  @Override
  public int getStatus(){
    return RUNNING;
  }

  @Override
  public synchronized Vector<Identity> getIdentities() {
    removeDupulicates();
    Vector<Identity> v = new Vector();
    for(int i=0; i<identities.size(); i++){
      v.addElement(identities.get(i));
    }
    return v;
  }

  public synchronized void add(Identity identity) {
    if(!identities.contains(identity)) {
      byte[] blob1 = identity.getPublicKeyBlob();
      if(blob1 == null) {
        identities.add(identity);
        return;
      }
      for(int i = 0; i<identities.size(); i++){
        byte[] blob2 = identities.get(i).getPublicKeyBlob();
        if(blob2 != null && Util.array_equals(blob1, blob2)){
          if(!identity.isEncrypted() && identities.get(i).isEncrypted()){
            remove(blob2);
          }
          else {  
            return;
          }
        }
      }
      identities.add(identity);
    }
  }

  public synchronized boolean add(byte[] identity) {
    try{
      Identity _identity =
        IdentityFile.newInstance("from remote:", identity, null, jsch);
      add(_identity);
      return true;
    }
    catch(JSchException e){
      return false;
    }
  }

  synchronized void remove(Identity identity) {
    if(identities.contains(identity)) {
      identities.remove(identity);
      identity.clear();
    }
    else {
      remove(identity.getPublicKeyBlob());
    }
  }

  public synchronized boolean remove(byte[] blob) {
    if(blob == null) return false;
    for(int i=0; i<identities.size(); i++) {
      Identity _identity = (Identity)(identities.get(i));
      byte[] _blob = _identity.getPublicKeyBlob();
      if(_blob == null || !Util.array_equals(blob, _blob))
        continue;
      identities.remove(_identity);
      _identity.clear();
      return true;
    }
    return false;
  }

  public synchronized void removeAll() {
    for(int i=0; i<identities.size(); i++) {
      Identity identity=identities.get(i);
      identity.clear();
    }
    identities.clear();
  } 

  private void removeDupulicates(){
    List<byte[]> v = new Vector<>();
    int len = identities.size();
    if(len == 0) return;
    for(int i=0; i<len; i++){
      Identity foo = (Identity)identities.get(i);
      byte[] foo_blob = foo.getPublicKeyBlob();
      if(foo_blob == null) continue;
      for(int j=i+1; j<len; j++){
        Identity bar = (Identity)identities.get(j);
        byte[] bar_blob = bar.getPublicKeyBlob();
        if(bar_blob == null) continue;
        if(Util.array_equals(foo_blob, bar_blob) &&
           foo.isEncrypted() == bar.isEncrypted()){
          v.add(foo_blob);
          break;
        }
      }
    }
    for(int i=0; i<v.size(); i++){
      remove(v.get(i));
    }
  }
}
