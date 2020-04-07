import { ViispAuthClient } from '../client';
import { Client as SoapClient } from 'soap';
import sinon from 'sinon';
import { getValidatedIdentity } from '../utils';
import { IidentityResponse } from '../types';
const soapStub = require('soap/soap-stub');

const urlMyApplicationWillUseWithCreateClient = 'http://path-to-my-wsdl';
const clientStub = {
  ExternalAuthenticationServiceImplService: {
    ExternalAuthenticationServiceImplPort: {
      initAuthentication: sinon.stub(),
      getAuthenticationData: sinon.stub(),
    },
  },
};

const identityData = {
  attributes: {
    id: 'uniqueId',
  },
  authenticationAttribute: [
    {
      attribute: 'lt-personal-code',
      value: '51001091072',
    },
  ],
  authenticationProvider: 'auth.signatureProvider',
  sourceData: {
    parameter: [
      {
        $value: 'EE',
        attributes: {
          name: 'C',
        },
      },
      {
        $value:
          'OjpkGwvfJWGtkaBS_0tc69R9IwbNxpN86fGy_zaeVqNtz1mSBuEGj6yn-1wDWMoZCiYaUr9ThkRp9PVkKqAaSo-yXNKYfIToRrhwlugvNUWIcpH94cTxf70wQFnWDlfPZFb0-z8ESI0STcebfsUZFQfQE9PDmJMlc7Wjzy1ZmvI',
        attributes: {
          name: 'data',
        },
      },
      {
        $value: 'TEST of EID-SK 2011',
        attributes: {
          name: 'CN',
        },
      },
      {
        $value: 'pki@sk.ee',
        attributes: {
          name: 'OID.1.2.840.113549.1.9.1',
        },
      },
      {
        $value: 'AS Sertifitseerimiskeskus',
        attributes: {
          name: 'O',
        },
      },
    ],
    type: 'BANKLINK',
  },
  userInformation: [
    {
      information: 'firstName',
      value: {
        stringValue: 'Testas',
      },
    },
    {
      information: 'lastName',
      value: {
        stringValue: 'Testas',
      },
    },
    {
      information: 'companyName',
      value: null,
    },
  ],
};

const validatedIdentityResponse: IidentityResponse = getValidatedIdentity(identityData);

const ticketData = { ticket: '1234' };

(clientStub.ExternalAuthenticationServiceImplService.ExternalAuthenticationServiceImplPort
  .initAuthentication as any).respondWithSuccess = soapStub.createRespondingStub(ticketData);
(clientStub.ExternalAuthenticationServiceImplService.ExternalAuthenticationServiceImplPort
  .getAuthenticationData as any).respondWithSuccess = soapStub.createRespondingStub(identityData);

soapStub.registerClient('my client alias', urlMyApplicationWillUseWithCreateClient, clientStub);

describe('VIISP auth', () => {
  let clientStub: SoapClient;
  let instance: ViispAuthClient;

  beforeEach(() => {
    clientStub = soapStub.getStub('my client alias');
    soapStub.reset();
    instance = new ViispAuthClient(clientStub);
  });

  describe('client', function () {
    beforeEach(async () => {
      clientStub.ExternalAuthenticationServiceImplService.ExternalAuthenticationServiceImplPort.initAuthentication.respondWithSuccess();
      clientStub.ExternalAuthenticationServiceImplService.ExternalAuthenticationServiceImplPort.getAuthenticationData.respondWithSuccess();
    });

    it('should get a ticket', async () => {
      const ticket = await instance.getTicket();
      expect(ticket).toBe(ticketData.ticket);
    });

    it('should init instance and then do remote calls with provided certs', async () => {
      await ViispAuthClient.storeCertificates();
      expect(ViispAuthClient.soapClientCert).toBeDefined();
      expect(ViispAuthClient.soapClientCertKey).toBeDefined();
    });

    it('should get an identity', async () => {
      const ticket = await instance.getTicket();
      const identity = await instance.getIdentity(ticket);
      expect(identity.toString()).toBe(validatedIdentityResponse.toString());
    });
  });
});
