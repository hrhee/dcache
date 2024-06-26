/* dCache - http://www.dcache.org/
 *
 * Copyright (C) 2020-2023 Deutsches Elektronen-Synchrotron
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.dcache.gplazma.oidc.profiles;

import static org.dcache.auth.attributes.Activity.DOWNLOAD;
import static org.dcache.auth.attributes.Activity.LIST;
import static org.dcache.auth.attributes.Activity.READ_METADATA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import diskCacheV111.util.FsPath;
import java.util.Optional;

import org.dcache.auth.attributes.Activity;
import org.dcache.auth.attributes.MultiTargetedRestriction.Authorisation;
import org.junit.Test;

public class WlcgProfileScopeTest {

    @Test(expected=InvalidScopeException.class)
    public void shouldRejectUnknownScope() {
        new WlcgProfileScope("unknown-value");
    }

    @Test
    public void shouldIdentifyStorageReadScope() {
        assertTrue(WlcgProfileScope.isWlcgProfileScope("storage.read:/"));
    }

    @Test
    public void shouldIdentifyStorageCreateScope() {
        assertTrue(WlcgProfileScope.isWlcgProfileScope("storage.create:/"));
    }

    @Test
    public void shouldIdentifyStorageModifyScope() {
        assertTrue(WlcgProfileScope.isWlcgProfileScope("storage.modify:/"));
    }

    @Test
    public void shouldIdentifyStorageStageScope() {
        assertTrue(WlcgProfileScope.isWlcgProfileScope("storage.stage:/"));
    }

    @Test
    public void shouldNotIdentifyStorageWriteScope() {
        assertFalse(WlcgProfileScope.isWlcgProfileScope("storage.write:/"));
    }


    @Test(expected = InvalidScopeException.class)
    public void shouldRejectStorageCreateScopeWithoutPath() {
        new WlcgProfileScope("storage.create");
    }

    @Test(expected = InvalidScopeException.class)
    public void shouldRejectStorageReadScopeWithoutPath() {
        new WlcgProfileScope("storage.read");
    }

    @Test(expected = InvalidScopeException.class)
    public void shouldRejectStorageStageScopeWithoutPath() {
        new WlcgProfileScope("storage.stage");
    }

    @Test(expected = InvalidScopeException.class)
    public void shouldRejectStorageModifyScopeWithoutPath() {
        new WlcgProfileScope("storage.modify");
    }

    @Test
    public void shouldIdentifyComputeReadScope() {
        assertTrue(WlcgProfileScope.isWlcgProfileScope("compute.read"));
    }

    @Test
    public void shouldIdentifyComputeModifyScope() {
        assertTrue(WlcgProfileScope.isWlcgProfileScope("compute.modify"));
    }

    @Test
    public void shouldIdentifyComputeCreateScope() {
        assertTrue(WlcgProfileScope.isWlcgProfileScope("compute.create"));
    }

    @Test
    public void shouldIdentifyComputeCancelScope() {
        assertTrue(WlcgProfileScope.isWlcgProfileScope("compute.cancel"));
    }

    @Test
    public void shouldParseReadScopeWithRootResourcePath() {
        WlcgProfileScope scope = new WlcgProfileScope("storage.read:/");

        Optional<Authorisation> maybeAuth = scope.authorisation(FsPath.create("/VOs/wlcg"));

        assertTrue(maybeAuth.isPresent());

        Authorisation auth = maybeAuth.get();

        assertThat(auth.getPath(), equalTo(FsPath.create("/VOs/wlcg")));
        assertThat(auth.getActivity(), containsInAnyOrder(LIST, READ_METADATA, DOWNLOAD));
    }

    @Test
    public void shouldParseStageScopeWithRootResourcePath() {
        WlcgProfileScope scope = new WlcgProfileScope("storage.stage:/");

        Optional<Authorisation> maybeAuth = scope.authorisation(FsPath.create("/VOs/wlcg"));

        assertTrue(maybeAuth.isPresent());

        Authorisation auth = maybeAuth.get();

        assertThat(auth.getPath(), equalTo(FsPath.create("/VOs/wlcg")));
        assertThat(auth.getActivity(), containsInAnyOrder(LIST, READ_METADATA, DOWNLOAD, Activity.STAGE));
    }

    @Test
    public void shouldParseReadScopeWithNonRootResourcePath() {
        WlcgProfileScope scope = new WlcgProfileScope("storage.read:/foo");

        Optional<Authorisation> maybeAuth = scope.authorisation(FsPath.create("/VOs/wlcg"));

        assertTrue(maybeAuth.isPresent());

        Authorisation auth = maybeAuth.get();

        assertThat(auth.getPath(), equalTo(FsPath.create("/VOs/wlcg/foo")));
        assertThat(auth.getActivity(), containsInAnyOrder(LIST, READ_METADATA, DOWNLOAD));
    }

    @Test
    public void shouldParseStageScopeWithNonRootResourcePath() {
        WlcgProfileScope scope = new WlcgProfileScope("storage.stage:/foo");

        Optional<Authorisation> maybeAuth = scope.authorisation(FsPath.create("/VOs/wlcg"));

        assertTrue(maybeAuth.isPresent());

        Authorisation auth = maybeAuth.get();

        assertThat(auth.getPath(), equalTo(FsPath.create("/VOs/wlcg/foo")));
        assertThat(auth.getActivity(), containsInAnyOrder(LIST, READ_METADATA, DOWNLOAD, Activity.STAGE));
    }

    @Test(expected=InvalidScopeException.class)
    public void shouldRejectReadScopeWithRelativeResourcePath() {
        new WlcgProfileScope("storage.read:foo");
    }

    @Test(expected=InvalidScopeException.class)
    public void shouldRejectStageScopeWithRelativeResourcePath() {
        new WlcgProfileScope("storage.stage:foo");
    }

    @Test
    public void shouldParseComputeReadScope() {
        WlcgProfileScope scope = new WlcgProfileScope("compute.read");

        Optional<Authorisation> maybeAuth = scope.authorisation(FsPath.create("/VOs/wlcg"));

        assertTrue(maybeAuth.isEmpty());
    }

    @Test
    public void shouldParseComputeModifyScope() {
        WlcgProfileScope scope = new WlcgProfileScope("compute.modify");

        Optional<Authorisation> maybeAuth = scope.authorisation(FsPath.create("/VOs/wlcg"));

        assertTrue(maybeAuth.isEmpty());
    }

    @Test
    public void shouldParseComputeCreateScope() {
        WlcgProfileScope scope = new WlcgProfileScope("compute.create");

        Optional<Authorisation> maybeAuth = scope.authorisation(FsPath.create("/VOs/wlcg"));

        assertTrue(maybeAuth.isEmpty());
    }

    @Test
    public void shouldParseComputeCancelScope() {
        WlcgProfileScope scope = new WlcgProfileScope("compute.cancel");

        Optional<Authorisation> maybeAuth = scope.authorisation(FsPath.create("/VOs/wlcg"));

        assertTrue(maybeAuth.isEmpty());
    }
}
