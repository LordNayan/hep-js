var chai = require('chai');
var should = chai.should();
var expect = chai.expect;
var hepnode = require('../index');

describe('#escape', function() {
  it('HEP Encoder', function() {
    hepnode.encode('HEP3').should.equal('HEP3').toString("binary");
  });
});

describe('#unescape', function() {
  it('HEP Decoder', function() {
    hepnode.decode(('HEP3').toString("binary")).should.equal('HEP3');
  });
});

describe('#validateHepPacket', function() {
  it('should return true for a valid HEP packet', function() {
    const validPacket = {
      rcinfo: {
        protocolFamily: 2,
        protocol: 17,
        srcIp: '192.168.1.1',
        dstIp: '192.168.1.2',
        srcPort: 5060,
        dstPort: 5060,
        timeSeconds: 1623412568,
        timeUseconds: 123456,
        payloadType: 1,
        captureId: 123
      },
      payload: 'SIP/2.0 200 OK'
    };
    hepnode.validateHepPacket(validPacket).should.be.true;
  });

  it('should return false for an invalid HEP packet', function() {
    const invalidPacket = {
      rcinfo: {
        protocol: 17,
        srcIp: '192.168.1.1',
        dstIp: '192.168.1.2',
        srcPort: 5060,
        dstPort: 5060
      },
      payload: 'SIP/2.0 200 OK'
    };
    hepnode.validateHepPacket(invalidPacket).should.be.false;
  });
});

describe('#extractFields', function() {
  const testPacket = {
    rcinfo: {
      protocolFamily: 2,
      protocol: 17,
      srcIp: '192.168.1.1',
      dstIp: '192.168.1.2',
      srcPort: 5060,
      dstPort: 5060,
      timeSeconds: 1623412568,
      timeUseconds: 123456,
      payloadType: 1,
      captureId: 123
    },
    payload: 'SIP/2.0 200 OK'
  };

  it('should extract specified fields from a valid HEP packet', function() {
    const fields = ['srcIp', 'dstIp', 'srcPort', 'dstPort', 'payload'];
    const result = hepnode.extractFields(testPacket, fields);
    expect(result).to.deep.equal({
      srcIp: '192.168.1.1',
      dstIp: '192.168.1.2',
      srcPort: 5060,
      dstPort: 5060,
      payload: 'SIP/2.0 200 OK'
    });
  });

  it('should throw an error for an invalid HEP packet', function() {
    const invalidPacket = { rcinfo: { srcIp: '192.168.1.1' } };
    const fields = ['srcIp', 'dstIp'];
    expect(() => hepnode.extractFields(invalidPacket, fields)).to.throw('Invalid HEP packet');
  });
});