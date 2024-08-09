import { TreeSSKG } from "../sskg";

it("Create two SSKG will result in two different initial keys", async () => {
    const sskg1 = await TreeSSKG.genSSK(10);
    const sskg2 = await TreeSSKG.genSSK(10);
    expect(await sskg1.getKey()).not.toStrictEqual(await sskg2.getKey());
});
