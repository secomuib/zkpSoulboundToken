import {
  getCoinMarketCapApiKey,
  getEtherscanApiKey,
  getInfuraApiKey,
  getPrivateKey
} from "./src/EnvParams";
import "hardhat-deploy";
import "@nomiclabs/hardhat-ethers";
import "@nomiclabs/hardhat-solhint";
import "@nomiclabs/hardhat-etherscan";
import "@typechain/ethers-v5";
import "@typechain/hardhat";
import "hardhat-gas-reporter";
import "solidity-coverage";
import { NetworksUserConfig } from "hardhat/types";

const getInfuraURL = (network: string) => {
  return `https://${network}.infura.io/v3/${getInfuraApiKey()}`;
};

const networks: NetworksUserConfig = {
  hardhat: {
    allowUnlimitedContractSize: true,
    gasPrice: "auto"
  },
  sepolia: {
    url: getInfuraURL("sepolia"),
    chainId: 11155111,
    accounts: [getPrivateKey()]
  },
  mainnet: {
    url: getInfuraURL("mainnet"),
    chainId: 1,
    accounts: [getPrivateKey()]
  }
};

export default {
  networks,

  solidity: {
    compilers: [
      {
        version: "0.6.11",
        settings: {
          optimizer: {
            enabled: true,
            runs: 1,
            details: {
              yul: false
            }
          }
        }
      },
      {
        version: "0.8.18",
        settings: {
          optimizer: {
            enabled: true,
            runs: 1,
            details: {
              yul: false
            }
          }
        }
      }
    ]
  },
  namedAccounts: {
    deployer: {
      default: 0
    }
  },
  etherscan: {
    apiKey: getEtherscanApiKey()
  },
  gasReporter: {
    currency: "USD",
    coinmarketcap: getCoinMarketCapApiKey(),
    token: "MATIC",
    gasPriceApi:
      "https://api.polygonscan.com/api?module=proxy&action=eth_gasPrice"
  },
  typechain: {
    outDir: "typechain"
  }
};
