import { expect } from "chai";
import { ethers } from "hardhat";

describe("Security patch: bounded distribution and authorized relayed claims", function () {
  async function deployToken() {
    const Token = await ethers.getContractFactory("MockERC20");
    const token = await Token.deploy("Mock", "MOCK", 18);
    return token;
  }

  describe("DistributionRouter", function () {
    it("rejects a chunk above the gas-safe recipient limit", async function () {
      const [owner, treasury, sender, ...accounts] = await ethers.getSigners();
      const token = await deployToken();

      const Router = await ethers.getContractFactory("DistributionRouter");
      const router = await Router.deploy(owner.address, treasury.address, 300);

      const recipients = accounts.slice(0, 51).map((s) => s.address);
      const amounts = recipients.map(() => 1n);

      await token.mint(sender.address, 1_000n);
      await token.connect(sender).approve(await router.getAddress(), 1_000n);

      await expect(
        router.connect(sender).distributeChunk(await token.getAddress(), recipients, amounts)
      )
        .to.be.revertedWithCustomError(router, "ChunkTooLarge")
        .withArgs(51n, 50n);
    });

    it("moves a valid chunk atomically and sends the exact fee to treasury", async function () {
      const [owner, treasury, sender, alice, bob] = await ethers.getSigners();
      const token = await deployToken();

      const Router = await ethers.getContractFactory("DistributionRouter");
      const router = await Router.deploy(owner.address, treasury.address, 300);

      const amounts = [1_000n, 2_000n];
      const gross = 3_000n;
      const fee = 90n;

      await token.mint(sender.address, gross + fee);
      await token.connect(sender).approve(await router.getAddress(), gross + fee);

      await expect(
        router.connect(sender).distributeChunk(
          await token.getAddress(),
          [alice.address, bob.address],
          amounts
        )
      )
        .to.emit(router, "Distributed")
        .withArgs(sender.address, await token.getAddress(), 2n, gross, fee);

      expect(await token.balanceOf(alice.address)).to.equal(1_000n);
      expect(await token.balanceOf(bob.address)).to.equal(2_000n);
      expect(await token.balanceOf(treasury.address)).to.equal(fee);
      expect(await token.balanceOf(await router.getAddress())).to.equal(0n);
    });
  });

  describe("RewardClaimer", function () {
    async function fixture() {
      const [owner, recipient, relayer, attacker] = await ethers.getSigners();
      const token = await deployToken();

      const index = 7n;
      const amount = 500n;
      const leaf = ethers.keccak256(
        ethers.solidityPacked(["bytes32"], [
          ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
              ["uint256", "address", "uint256"],
              [index, recipient.address, amount]
            )
          ),
        ])
      );

      const Claimer = await ethers.getContractFactory("RewardClaimer");
      const claimer = await Claimer.deploy(
        owner.address,
        await token.getAddress(),
        leaf
      );

      await token.mint(await claimer.getAddress(), amount);
      return { owner, recipient, relayer, attacker, token, claimer, index, amount };
    }

    it("allows direct recipient claims", async function () {
      const { recipient, token, claimer, index, amount } = await fixture();

      await claimer.connect(recipient).claim(index, amount, []);
      expect(await token.balanceOf(recipient.address)).to.equal(amount);
      expect(await claimer.isClaimed(0, index)).to.equal(true);
    });

    it("rejects unsolicited relay claims", async function () {
      const { attacker, recipient, claimer, index, amount } = await fixture();

      await expect(
        claimer.connect(attacker).claimFor(
          index,
          recipient.address,
          amount,
          [],
          attacker.address,
          BigInt((await ethers.provider.getBlock("latest"))!.timestamp + 3600),
          "0x"
        )
      ).to.be.reverted;
    });

    it("accepts a recipient-authorized relayer and credits only the recipient", async function () {
      const { recipient, relayer, token, claimer, index, amount } = await fixture();
      const network = await ethers.provider.getNetwork();
      const deadline = BigInt((await ethers.provider.getBlock("latest"))!.timestamp + 3600);

      const signature = await recipient.signTypedData(
        {
          name: "RWAForge RewardClaimer",
          version: "1",
          chainId: network.chainId,
          verifyingContract: await claimer.getAddress(),
        },
        {
          ClaimFor: [
            { name: "index", type: "uint256" },
            { name: "account", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "merkleRoot", type: "bytes32" },
            { name: "relayer", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "deadline", type: "uint256" },
          ],
        },
        {
          index,
          account: recipient.address,
          amount,
          merkleRoot: await claimer.merkleRoot(),
          relayer: relayer.address,
          nonce: 0n,
          deadline,
        }
      );

      await claimer.connect(relayer).claimFor(
        index,
        recipient.address,
        amount,
        [],
        relayer.address,
        deadline,
        signature
      );

      expect(await token.balanceOf(recipient.address)).to.equal(amount);
      expect(await token.balanceOf(relayer.address)).to.equal(0n);
      expect(await claimer.nonces(recipient.address)).to.equal(1n);
    });

    it("rejects replay of an already-consumed relay authorization", async function () {
      const { recipient, relayer, claimer, index, amount } = await fixture();
      const network = await ethers.provider.getNetwork();
      const deadline = BigInt((await ethers.provider.getBlock("latest"))!.timestamp + 3600);

      const signature = await recipient.signTypedData(
        {
          name: "RWAForge RewardClaimer",
          version: "1",
          chainId: network.chainId,
          verifyingContract: await claimer.getAddress(),
        },
        {
          ClaimFor: [
            { name: "index", type: "uint256" },
            { name: "account", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "merkleRoot", type: "bytes32" },
            { name: "relayer", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "deadline", type: "uint256" },
          ],
        },
        {
          index,
          account: recipient.address,
          amount,
          merkleRoot: await claimer.merkleRoot(),
          relayer: relayer.address,
          nonce: 0n,
          deadline,
        }
      );

      await claimer.connect(relayer).claimFor(
        index, recipient.address, amount, [], relayer.address, deadline, signature
      );

      await expect(
        claimer.connect(relayer).claimFor(
          index, recipient.address, amount, [], relayer.address, deadline, signature
        )
      ).to.be.reverted;
    });
  });
});
