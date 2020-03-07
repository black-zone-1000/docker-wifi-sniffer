from scapy.packet import Packet
import json
import base64
import binascii


class JsonPacket(Packet):
    name = "JsonPacket"
    fields_desc = []
    json_valid_types = (str, bytes, int, float, bool, None)

    # Override
    def build_done(self, pkt):
        jsonized = self._jsonize_packet(pkt)
        return json.dumps(jsonized, ensure_ascii=False, indent=4)

    def _jsonize_packet(self, pkt):
        out = []
        for layer in self._walk_layers(pkt):
            layer_name = layer.name if layer.name else layer.__name__
            out.append({layer_name: self._serialize_fields(layer, {})})
        return out

    def _walk_layers(self, pkt):
        i = 1
        layer = self.getlayer(i)
        while layer:
            yield layer
            i += 1
            layer = self.getlayer(i)

    def _serialize_fields(self, layer, serialized_fields={}):
        if hasattr(layer, "fields_desc"):
            for field in layer.fields_desc:
                self._extract_fields(layer, field, serialized_fields)
        return serialized_fields

    def _extract_fields(self, layer, field, extracted={}):
        value = layer.__getattr__(field.name)
        if type(value) in self.json_valid_types:
            if type(value) == bytes:
                extracted.update({field.name: binascii.hexlify(value).decode('UTF-8')})
            else:
                extracted.update({field.name: value})
        else:
            local_serialized = {}
            extracted.update({field.name: local_serialized})
            self._serialize_fields(field, local_serialized)
