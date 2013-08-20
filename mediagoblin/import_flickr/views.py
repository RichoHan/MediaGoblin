# GNU MediaGoblin -- federated, autonomous media hosting
# Copyright (C) 2011, 2012 MediaGoblin contributors.  See AUTHORS.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from mediagoblin import messages
import mediagoblin.mg_globals as mg_globals
from os.path import splitext

import logging
import uuid
import zipfile
import imghdr
from xml.etree import ElementTree
_log = logging.getLogger(__name__)


from mediagoblin.tools.text import convert_to_tag_list_of_dicts
from mediagoblin.tools.translate import pass_to_ugettext as _
from mediagoblin.tools.response import render_to_response, redirect
from mediagoblin.decorators import require_active_login
from mediagoblin.import_flickr import forms as submit_forms
from mediagoblin.messages import add_message, SUCCESS
from mediagoblin.media_types import sniff_media, \
    InvalidFileType, FileTypeNotSupported
from mediagoblin.import_flickr.lib import check_file_field, prepare_queue_task, \
    run_process_media, new_upload_entry

from mediagoblin.notifications import add_comment_subscription


@require_active_login
def submit_start(request):
    """
    First view for submitting a file.
    """
    submit_form = submit_forms.SubmitStartForm(request.form,
        license=request.user.license_preference)

    if request.method == 'POST' and submit_form.validate():
        if not check_file_field(request, 'file'):
            submit_form.file.errors.append(
                _(u'You must provide a file.'))
        else:
            try:
                filename = request.files['file'].filename

                # If the filename contains non ascii generate a unique name
                if not all(ord(c) < 128 for c in filename):
                    filename = unicode(uuid.uuid4()) + splitext(filename)[-1]

		#-----Test log-----
		print type(request)
		print type(request.files['file'])
		print request.files['file'].stream
		print "-----Test log-----File name: " + filename

                # Sniff the submitted media to determine which
                # media plugin should handle processing
                media_type, media_manager = sniff_media(
                    request.files['file'])

		print "-------------------File Data------------------------"
                zf = zipfile.ZipFile(request.files['file'], 'r')
                for name in zf.namelist():
                        try:
                                data = zf.read(name)
                                if imghdr.what(name, data):
					#print name.split(".")[0]
					metadata = ElementTree.ElementTree(ElementTree.fromstring(zf.read(name.split(".")[0]+'.xml')))

					img_title = metadata.find('title').text
					img_description = metadata.find('description').text
					img_tags = ''
					for tag in metadata.find('tags'):
						img_tags = img_tags + ', ' + tag.text
					print img_title
					print img_description
					print img_tags

					upload_data = data
                                        upload_filename = name.lstrip('dst/')

					# create entry and save in database
			                entry = new_upload_entry(request.user)
			                entry.media_type = unicode(media_type)
			                
					entry.title = unicode(img_title)#(
			                    #unicode(submit_form.title.data)
			                    #or unicode(splitext(request.files['file'].filename)[0]))

			                entry.description = unicode(img_description)#unicode(submit_form.description.data)

			                entry.license = unicode('http://creativecommons.org/publicdomain/mark/1.0/')#unicode(submit_form.license.data) or None

			                # Process the user's folksonomy "tags"
			                entry.tags = convert_to_tag_list_of_dicts(img_tags)
			                #    submit_form.tags.data)

			                # Generate a slug from the title
			                entry.generate_slug()

					queue_file = prepare_queue_task(request.app, entry, upload_filename)#filename)

			                with queue_file:
			                    queue_file.write(upload_data)#request.files['file'].stream.read())

					# Save now so we have this data before kicking off processing
			                entry.save()

					feed_url = request.urlgen(
			                    'mediagoblin.user_pages.atom_feed',
			                    qualified=True, user=request.user.username)
			                run_process_media(entry, feed_url)
                        except KeyError:
                                print 'ERROR: Did not find %s in zip file' % name
                print "----------------------------------------------------"

                # Pass off to processing
                #
                # (... don't change entry after this point to avoid race
                # conditions with changes to the document via processing code)
                add_message(request, SUCCESS, _('Woohoo! Submitted!'))

                add_comment_subscription(request.user, entry)

                return redirect(request, "mediagoblin.user_pages.user_home",
                                user=request.user.username)
            except Exception as e:
                '''
                This section is intended to catch exceptions raised in
                mediagoblin.media_types
                '''
                if isinstance(e, InvalidFileType) or \
                        isinstance(e, FileTypeNotSupported):
                    submit_form.file.errors.append(
                        e)
                else:
                    raise

    return render_to_response(
        request,
        'mediagoblin/import_flickr/start.html',
        {'submit_form': submit_form,
         'app_config': mg_globals.app_config})


"""@require_active_login
def add_collection(request, media=None):
    submit_form = submit_forms.AddCollectionForm(request.form)

    if request.method == 'POST' and submit_form.validate():
        collection = request.db.Collection()

        collection.title = unicode(submit_form.title.data)
        collection.description = unicode(submit_form.description.data)
        collection.creator = request.user.id
        collection.generate_slug()

        # Make sure this user isn't duplicating an existing collection
        existing_collection = request.db.Collection.query.filter_by(
                creator=request.user.id,
                title=collection.title).first()

        if existing_collection:
            add_message(request, messages.ERROR,
                _('You already have a collection called "%s"!') \
                    % collection.title)
        else:
            collection.save()

            add_message(request, SUCCESS,
                _('Collection "%s" added!') % collection.title)

        return redirect(request, "mediagoblin.user_pages.user_home",
                        user=request.user.username)

    return render_to_response(
        request,
        'mediagoblin/submit/collection.html',
        {'submit_form': submit_form,
         'app_config': mg_globals.app_config})"""
