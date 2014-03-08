/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include "bgp/ermvpn/ermvpn_route.h"

#include "base/logging.h"
#include "base/task.h"
#include "bgp/bgp_log.h"
#include "control-node/control_node.h"
#include "testing/gunit.h"

using namespace std;

class ErmVpnPrefixTest : public ::testing::Test {
};

TEST_F(ErmVpnPrefixTest, BuildNativePrefix) {
    boost::system::error_code ec;
    RouteDistinguisher rd(RouteDistinguisher::FromString("10.1.1.1:65535"));
    Ip4Address group(Ip4Address::from_string("224.1.2.3", ec));
    Ip4Address source(Ip4Address::from_string("192.168.1.1", ec));
    ErmVpnPrefix prefix(ErmVpnPrefix::NativeRoute, rd, group, source);
    EXPECT_TRUE(prefix.IsValid(prefix.type()));
    EXPECT_FALSE(prefix.IsValidForBgp(prefix.type()));
    EXPECT_EQ("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1", prefix.ToString());
    EXPECT_EQ("10.1.1.1:65535:224.1.2.3,192.168.1.1", prefix.ToXmppIdString());
    EXPECT_EQ(ErmVpnPrefix::NativeRoute, prefix.type());
    EXPECT_EQ("10.1.1.1:65535", prefix.route_distinguisher().ToString());
    EXPECT_EQ("0.0.0.0", prefix.router_id().to_string());
    EXPECT_EQ("224.1.2.3", prefix.group().to_string());
    EXPECT_EQ("192.168.1.1", prefix.source().to_string());
}

TEST_F(ErmVpnPrefixTest, ParseNativePrefix) {
    string prefix_str("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    EXPECT_TRUE(prefix.IsValid(prefix.type()));
    EXPECT_FALSE(prefix.IsValidForBgp(prefix.type()));
    EXPECT_EQ("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1", prefix.ToString());
    EXPECT_EQ("10.1.1.1:65535:224.1.2.3,192.168.1.1", prefix.ToXmppIdString());
    EXPECT_EQ(ErmVpnPrefix::NativeRoute, prefix.type());
    EXPECT_EQ("10.1.1.1:65535", prefix.route_distinguisher().ToString());
    EXPECT_EQ("0.0.0.0", prefix.router_id().to_string());
    EXPECT_EQ("224.1.2.3", prefix.group().to_string());
    EXPECT_EQ("192.168.1.1", prefix.source().to_string());
}

TEST_F(ErmVpnPrefixTest, BuildLocalPrefix) {
    boost::system::error_code ec;
    RouteDistinguisher rd(RouteDistinguisher::FromString("10.1.1.1:65535"));
    Ip4Address router_id(Ip4Address::from_string("9.8.7.6", ec));
    Ip4Address group(Ip4Address::from_string("224.1.2.3", ec));
    Ip4Address source(Ip4Address::from_string("192.168.1.1", ec));
    ErmVpnPrefix prefix(ErmVpnPrefix::LocalTreeRoute, rd, router_id, group, source);
    EXPECT_TRUE(prefix.IsValid(prefix.type()));
    EXPECT_TRUE(prefix.IsValidForBgp(prefix.type()));
    EXPECT_EQ("1-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1", prefix.ToString());
    EXPECT_EQ(ErmVpnPrefix::LocalTreeRoute, prefix.type());
    EXPECT_EQ("10.1.1.1:65535", prefix.route_distinguisher().ToString());
    EXPECT_EQ("9.8.7.6", prefix.router_id().to_string());
    EXPECT_EQ("224.1.2.3", prefix.group().to_string());
    EXPECT_EQ("192.168.1.1", prefix.source().to_string());
}

TEST_F(ErmVpnPrefixTest, ParseLocalPrefix) {
    string prefix_str("1-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    EXPECT_TRUE(prefix.IsValid(prefix.type()));
    EXPECT_TRUE(prefix.IsValidForBgp(prefix.type()));
    EXPECT_EQ(ErmVpnPrefix::LocalTreeRoute, prefix.type());
    EXPECT_EQ("10.1.1.1:65535", prefix.route_distinguisher().ToString());
    EXPECT_EQ("9.8.7.6", prefix.router_id().to_string());
    EXPECT_EQ("224.1.2.3", prefix.group().to_string());
    EXPECT_EQ("192.168.1.1", prefix.source().to_string());
}

TEST_F(ErmVpnPrefixTest, BuildGlobalPrefix) {
    boost::system::error_code ec;
    RouteDistinguisher rd(RouteDistinguisher::FromString("10.1.1.1:65535"));
    Ip4Address router_id(Ip4Address::from_string("9.8.7.6", ec));
    Ip4Address group(Ip4Address::from_string("224.1.2.3", ec));
    Ip4Address source(Ip4Address::from_string("192.168.1.1", ec));
    ErmVpnPrefix prefix(ErmVpnPrefix::GlobalTreeRoute, rd, router_id, group, source);
    EXPECT_TRUE(prefix.IsValid(prefix.type()));
    EXPECT_TRUE(prefix.IsValidForBgp(prefix.type()));
    EXPECT_EQ("2-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1", prefix.ToString());
    EXPECT_EQ(ErmVpnPrefix::GlobalTreeRoute, prefix.type());
    EXPECT_EQ("10.1.1.1:65535", prefix.route_distinguisher().ToString());
    EXPECT_EQ("9.8.7.6", prefix.router_id().to_string());
    EXPECT_EQ("224.1.2.3", prefix.group().to_string());
    EXPECT_EQ("192.168.1.1", prefix.source().to_string());
}

TEST_F(ErmVpnPrefixTest, ParseGlobalPrefix) {
    string prefix_str("2-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    EXPECT_TRUE(prefix.IsValid(prefix.type()));
    EXPECT_TRUE(prefix.IsValidForBgp(prefix.type()));
    EXPECT_EQ(ErmVpnPrefix::GlobalTreeRoute, prefix.type());
    EXPECT_EQ("10.1.1.1:65535", prefix.route_distinguisher().ToString());
    EXPECT_EQ("9.8.7.6", prefix.router_id().to_string());
    EXPECT_EQ("224.1.2.3", prefix.group().to_string());
    EXPECT_EQ("192.168.1.1", prefix.source().to_string());
}

// No "-" to delineate the prefix type.
TEST_F(ErmVpnPrefixTest, Error1) {
    boost::system::error_code ec;
    string prefix_str("2:10.1.1.1:65535:9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

// Invalid prefix type.
TEST_F(ErmVpnPrefixTest, Error2) {
    boost::system::error_code ec;
    string prefix_str("9-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

// No "-" to delineate the rd.
TEST_F(ErmVpnPrefixTest, Error3) {
    boost::system::error_code ec;
    string prefix_str("2-10.1.1.1:65535:9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

// Bad rd.
TEST_F(ErmVpnPrefixTest, Error4) {
    boost::system::error_code ec;
    string prefix_str("2-10.1.1.1:65536-9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

// No "," to delineate the router-id.
TEST_F(ErmVpnPrefixTest, Error5) {
    boost::system::error_code ec;
    string prefix_str("2-10.1.1.1:65535-9.8.7.6:224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

// Bad router-id.
TEST_F(ErmVpnPrefixTest, Error6) {
    boost::system::error_code ec;
    string prefix_str("2-10.1.1.1:65535-9.8.7,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

// No "," to delineate the group.
TEST_F(ErmVpnPrefixTest, Error7) {
    boost::system::error_code ec;
    string prefix_str("2-10.1.1.1:65535-9.8.7.6,224.1.2.3:192.168.1.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

// Bad group address.
TEST_F(ErmVpnPrefixTest, Error8) {
    boost::system::error_code ec;
    string prefix_str("2-10.1.1.1:65535-9.8.7.6,224.1.2,192.168.1.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

// Bad source address.
TEST_F(ErmVpnPrefixTest, Error9) {
    boost::system::error_code ec;
    string prefix_str("2-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1");
    ErmVpnPrefix prefix = ErmVpnPrefix::FromString(prefix_str, &ec);
    EXPECT_NE(0, ec.value());
    EXPECT_EQ(ErmVpnPrefix::Invalid, prefix.type());
}

class ErmVpnRouteTest : public ::testing::Test {
};

TEST_F(ErmVpnRouteTest, NativeToString) {
    string prefix_str("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix);
    EXPECT_EQ(prefix, route.GetPrefix());
    EXPECT_EQ("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1", route.ToString());
    EXPECT_EQ("10.1.1.1:65535:224.1.2.3,192.168.1.1", route.ToXmppIdString());
}

TEST_F(ErmVpnRouteTest, NativeIsValid1) {
    string prefix_str("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix);
    route.MarkDelete();
    EXPECT_FALSE(route.IsValid());
}

TEST_F(ErmVpnRouteTest, NativeIsValid2) {
    string prefix_str("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix);
    EXPECT_FALSE(route.IsValid());
}

TEST_F(ErmVpnRouteTest, NativeIsValid3) {
    string prefix_str("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix);
    BgpAttr attr;
    BgpPath path(NULL, 0, BgpPath::Local, &attr, 0, 0);
    route.InsertPath(&path);
    EXPECT_FALSE(route.IsValid());
}

TEST_F(ErmVpnRouteTest, NativeIsValid4) {
    string prefix_str("0-10.1.1.1:65535-0.0.0.0,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix);
    BgpAttr attr;
    LabelBlockPtr label_block(new LabelBlock(1000, 1999));
    attr.set_label_block(label_block);
    BgpPath path(NULL, 0, BgpPath::Local, &attr, 0, 0);
    route.InsertPath(&path);
    EXPECT_TRUE(route.IsValid());
}

TEST_F(ErmVpnRouteTest, LocalToString) {
    string prefix_str("1-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix);
    EXPECT_EQ(prefix, route.GetPrefix());
    EXPECT_EQ("1-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1", route.ToString());
}

TEST_F(ErmVpnRouteTest, LocalProtoPrefix) {
    string prefix_str("1-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix1(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix1);
    BgpProtoPrefix proto_prefix;
    route.BuildProtoPrefix(&proto_prefix, 0);
    ErmVpnPrefix prefix2(proto_prefix);
    EXPECT_EQ(ErmVpnPrefix::LocalTreeRoute, proto_prefix.type);
    EXPECT_EQ(22 * 8, proto_prefix.prefixlen);
    EXPECT_EQ(22, proto_prefix.prefix.size());
    EXPECT_EQ(prefix1, prefix2);
}

TEST_F(ErmVpnRouteTest, GlobalToString) {
    string prefix_str("2-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix);
    EXPECT_EQ(prefix, route.GetPrefix());
    EXPECT_EQ("2-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1", route.ToString());
}

TEST_F(ErmVpnRouteTest, GlobalProtoPrefix) {
    string prefix_str("2-10.1.1.1:65535-9.8.7.6,224.1.2.3,192.168.1.1");
    ErmVpnPrefix prefix1(ErmVpnPrefix::FromString(prefix_str));
    ErmVpnRoute route(prefix1);
    BgpProtoPrefix proto_prefix;
    route.BuildProtoPrefix(&proto_prefix, 0);
    ErmVpnPrefix prefix2(proto_prefix);
    EXPECT_EQ(ErmVpnPrefix::GlobalTreeRoute, proto_prefix.type);
    EXPECT_EQ(22 * 8, proto_prefix.prefixlen);
    EXPECT_EQ(22, proto_prefix.prefix.size());
    EXPECT_EQ(prefix1, prefix2);
}

int main(int argc, char **argv) {
    bgp_log_test::init();
    ::testing::InitGoogleTest(&argc, argv);
    ControlNode::SetDefaultSchedulingPolicy();
    int result = RUN_ALL_TESTS();
    TaskScheduler::GetInstance()->Terminate();
    return result;
}
