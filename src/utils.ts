import fs from 'fs';
import { promisify } from 'util';
import moment from 'moment';
import { SexAndSenturyMap, IidentityResponse } from './types';

export const readFileAsync = promisify(fs.readFile);

const SEX_AND_SENTURY_MAP: SexAndSenturyMap = {
  3: {
    key: 3,
    sex: 'male',
    century: 'XX',
  },
  4: {
    key: 4,
    sex: 'female',
    century: 'XX',
  },
  5: {
    key: 5,
    sex: 'male',
    century: 'XXI',
  },
  6: {
    key: 6,
    sex: 'female',
    century: 'XXI',
  },
};

const getSexFromId = (personalId: string) => {
  const sexStr = personalId.substr(0, 1);
  const sexObject = SEX_AND_SENTURY_MAP[sexStr];
  return sexObject.sex;
};

const getDateFromId = (personalId: string) => {
  const sexStr = personalId.substr(0, 1);
  const sexObject = SEX_AND_SENTURY_MAP[sexStr];
  const dateStr = personalId.substr(1, 7);

  moment.parseTwoDigitYear = function (year) {
    return sexObject.key < 5 ? parseInt(year, 10) + 1900 : parseInt(year, 10) + 2000;
  };

  return moment(dateStr, 'YYMMDD').format('YYYY-MM-DD');
};

export const getValidatedIdentity = (identity: any): IidentityResponse => {
  if (!identity.authenticationAttribute || !identity.userInformation) {
    return null;
  }

  const userInfo = identity.userInformation.reduce(
    (acc: any, curr: any) => ({
      ...acc,
      ...{
        [curr.information]: curr.value && curr.value.stringValue ? curr.value.stringValue : null,
      },
    }),
    {}
  );

  const identityData = identity.authenticationAttribute.reduce((acc: any, curr: any) => {
    let attribute;

    if (curr.attribute === 'lt-personal-code') {
      attribute = 'personalIdentityCode';
    } else if (curr.attribute === 'lt-company-code') {
      attribute = 'companyIdentityCode';
    } else if (curr.attribute === 'lt-employee-code') {
      attribute = 'governmentEmployeeCode';
    } else {
      attribute = 'unknownPropery';
    }

    return {
      ...acc,
      ...{
        [attribute]: curr.value,
      },
    };
  }, {});

  if (!userInfo.firstName || !userInfo.lastName || !identityData.personalIdentityCode) {
    return null;
  }

  const birthdate = getDateFromId(identityData.personalIdentityCode);
  const sex = getSexFromId(identityData.personalIdentityCode);

  if (!birthdate || !getSexFromId) {
    return null;
  }

  let extraData = {
    birthdate,
    sex,
  };

  if (userInfo.companyName) {
    extraData = { ...extraData, ...{ companyName: userInfo.companyName } };
  }

  return {
    firstName: userInfo.firstName,
    lastName: userInfo.lastName,
    ...extraData,
  };
};
